"""OSV POST /v1/query pagination: following tokens, stall guards, dedupe, sort, and caps.

The mocked OSV returns pages keyed by the request's page_token, so each test controls
exactly which page and token come back (see docs/api-notes.md for the real behavior).
"""

import asyncio
import json
import logging

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients import osv
from vuln_triage_mcp.clients.osv import (
    BASE_URL,
    MAX_QUERY_PAGES,
    MAX_QUERY_RESULTS,
    PAGINATION_STALLED,
    OSVClient,
)
from vuln_triage_mcp.server import mcp

QUERY_URL = f"{BASE_URL}/query"
PACKAGE = {"name": "linux", "ecosystem": "Debian:12"}
LABEL_SCORES = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.0}


def adv(vuln_id: str, label: str | None = "MODERATE") -> dict:
    """Minimal OSV advisory; the GHSA label gives a known approximate CVSS score."""
    record = {"id": vuln_id, "summary": f"summary of {vuln_id}"}
    if label:
        record["database_specific"] = {"severity": label}
    return record


def page(*vulns: dict, token: str | None = None) -> dict:
    body: dict = {"vulns": list(vulns)}
    if token:
        body["next_page_token"] = token
    return body


def mock_pages(pages: dict[str | None, dict | Exception]) -> respx.Route:
    """Serve pages[page_token] (None = first page); an Exception value is raised instead.

    An unknown token gets HTTP 400 rather than a KeyError: a non-HTTP exception raised
    inside a tool hangs the in-process fastmcp.Client (stdio returns an error normally),
    so a test that strays off the scripted pages must fail, not hang.
    """

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        token = body.get("page_token")
        if token not in pages:
            return httpx.Response(400, json={"message": f"unscripted page_token {token!r}"})
        result = pages[token]
        if isinstance(result, Exception):
            raise result
        if isinstance(result, httpx.Response):
            return result
        return httpx.Response(200, json=result)

    return respx.post(QUERY_URL).mock(side_effect=handler)


def sent_bodies(route: respx.Route) -> list[dict]:
    return [json.loads(call.request.read()) for call in route.calls]


def ids(result: dict) -> list[str]:
    return [v["id"] for v in result["vulns"]]


# --- Following tokens ---


@respx.mock
async def test_follows_tokens_across_pages(http):
    route = mock_pages(
        {
            None: page(adv("A-1"), adv("A-2"), token="t1"),
            "t1": page(adv("B-1"), adv("B-2"), token="t2"),
            "t2": page(adv("C-1")),
        }
    )

    result = await OSVClient(http).query_package("linux", "Debian:12", "6.1.0")

    assert sorted(ids(result)) == ["A-1", "A-2", "B-1", "B-2", "C-1"]
    assert (result["found_count"], result["returned_count"], result["pages"]) == (5, 5, 3)
    assert (result["truncated"], result["truncation_reason"]) == (False, None)
    # The token goes back as page_token, with the original package and version unchanged.
    query = {"package": PACKAGE, "version": "6.1.0"}
    assert sent_bodies(route) == [query, {**query, "page_token": "t1"}, {**query, "page_token": "t2"}]


@respx.mock
async def test_empty_token_ends_pagination(http):
    route = mock_pages({None: {"vulns": [adv("A-1")], "next_page_token": ""}})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert (route.call_count, result["truncated"]) == (1, False)


# --- Guard 1: pagination did not advance ---


@respx.mock
async def test_repeated_token_stops_with_stall_reason(http, caplog):
    route = mock_pages(
        {
            None: page(adv("A-1"), token="t1"),
            "t1": page(adv("B-1"), token="t1"),  # same token handed back
        }
    )

    with caplog.at_level(logging.WARNING, logger="vuln_triage_mcp.clients.osv"):
        result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert route.call_count == 2
    assert sorted(ids(result)) == ["A-1", "B-1"]  # what was collected is returned
    assert (result["truncated"], result["truncation_reason"]) == (True, PAGINATION_STALLED)
    assert PAGINATION_STALLED == "pagination did not advance"
    assert any("already-used page token" in r.message for r in caplog.records if r.levelno == logging.WARNING)


@respx.mock
async def test_token_from_an_earlier_page_stops(http):
    route = mock_pages(
        {
            None: page(adv("A-1"), token="t1"),
            "t1": page(adv("B-1"), token="t2"),
            "t2": page(adv("C-1"), token="t1"),  # cycles back
        }
    )

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert route.call_count == 3
    assert result["truncation_reason"] == PAGINATION_STALLED
    assert result["found_count"] == 3


@respx.mock
async def test_repeated_first_advisory_stops_and_drops_that_page(http, caplog):
    # The API-notes pitfall: a page that restarts from page 1 under a fresh token.
    route = mock_pages(
        {
            None: page(adv("A-1"), adv("A-2"), token="t1"),
            "t1": page(adv("A-1"), adv("NEW-1"), token="t2"),
            "t2": page(adv("C-1")),
        }
    )

    with caplog.at_level(logging.WARNING, logger="vuln_triage_mcp.clients.osv"):
        result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert route.call_count == 2  # stopped immediately; t2 never requested
    assert sorted(ids(result)) == ["A-1", "A-2"]  # the repeating page is not merged
    assert (result["pages"], result["truncated"], result["truncation_reason"]) == (1, True, PAGINATION_STALLED)
    assert any("repeats a previous page's first advisory A-1" in r.message for r in caplog.records)


@respx.mock
async def test_stall_reason_reaches_the_tool():
    mock_pages({None: page(adv("A-1"), token="t1"), "t1": page(adv("A-1"), token="t2")})

    async with Client(mcp) as client:
        result = (await client.call_tool("find_vulns_for_package", {"name": "linux", "ecosystem": "npm"})).structured_content

    assert (result["truncated"], result["truncation_reason"], result["found_count"]) == (True, "pagination did not advance", 1)


# --- Guard 2: dedupe by ID across pages, before sorting and capping ---


@respx.mock
async def test_dedupes_across_and_within_pages(http):
    mock_pages(
        {
            None: page(adv("A-1"), adv("SHARED"), adv("SHARED"), token="t1"),
            "t1": page(adv("B-1"), adv("SHARED"), adv("A-1")),
        }
    )

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert sorted(ids(result)) == ["A-1", "B-1", "SHARED"]
    assert result["found_count"] == 3


@respx.mock
async def test_dedupe_happens_before_the_cap(http):
    # 40 unique advisories, each repeated on a second page: 80 rows, but only 40 unique.
    first = [adv(f"V-{i:03d}") for i in range(40)]
    mock_pages({None: page(*first, token="t1"), "t1": page(adv("NEW-0"), *first)})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert result["found_count"] == 41
    assert len(result["vulns"]) == 41  # under the cap, so nothing is cut
    assert (result["truncated"], result["truncation_reason"]) == (False, None)


@respx.mock
async def test_first_occurrence_wins_on_duplicate(http):
    mock_pages({None: page(adv("DUP", "CRITICAL"), token="t1"), "t1": page(adv("X-1"), adv("DUP", "LOW"))})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    dup = next(v for v in result["vulns"] if v["id"] == "DUP")
    assert dup["cvss_score"] == 9.5


# --- Sorting and capping ---


@respx.mock
async def test_sorted_by_cvss_desc_unscored_last_ties_by_id(http):
    mock_pages(
        {
            None: page(adv("M-2", "MODERATE"), adv("N-1", None), adv("C-1", "CRITICAL"), token="t1"),
            "t1": page(adv("L-1", "LOW"), adv("M-1", "MODERATE"), adv("A-NONE", None), adv("H-1", "HIGH")),
        }
    )

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert ids(result) == ["C-1", "H-1", "M-1", "M-2", "L-1", "A-NONE", "N-1"]
    assert [v["cvss_score"] for v in result["vulns"]] == [9.5, 7.5, 5.0, 5.0, 2.0, None, None]


@respx.mock
async def test_cap_keeps_the_highest_cvss_across_pages(http):
    lows = [adv(f"LOW-{i:03d}", "LOW") for i in range(MAX_QUERY_RESULTS)]
    mock_pages({None: page(*lows, token="t1"), "t1": page(adv("ZZ-CRIT", "CRITICAL"))})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert ids(result)[0] == "ZZ-CRIT"  # from page 2, still ranked first
    assert len(result["vulns"]) == MAX_QUERY_RESULTS
    assert result["found_count"] == MAX_QUERY_RESULTS + 1
    assert result["returned_count"] == MAX_QUERY_RESULTS
    assert result["truncation_reason"] == f"showing the {MAX_QUERY_RESULTS} highest-CVSS of {MAX_QUERY_RESULTS + 1} advisories"


@respx.mock
async def test_stall_and_cap_reasons_combine(http):
    many = [adv(f"V-{i:03d}") for i in range(MAX_QUERY_RESULTS + 5)]
    mock_pages({None: page(*many, token="t1"), "t1": page(adv("X"), token="t1")})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert result["truncation_reason"] == (
        f"{PAGINATION_STALLED}; showing the {MAX_QUERY_RESULTS} highest-CVSS of {MAX_QUERY_RESULTS + 6} advisories"
    )


# --- Page and time budget ---


@respx.mock
async def test_page_limit(http):
    route = mock_pages({None: page(adv("P-0"), token="t1"), **{f"t{i}": page(adv(f"P-{i}"), token=f"t{i + 1}") for i in range(1, 10)}})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert route.call_count == MAX_QUERY_PAGES
    assert (result["pages"], result["found_count"]) == (MAX_QUERY_PAGES, MAX_QUERY_PAGES)
    assert result["truncation_reason"] == f"page limit of {MAX_QUERY_PAGES} reached"


@respx.mock
async def test_time_budget_keeps_collected_pages(http, monkeypatch):
    monkeypatch.setattr(osv, "QUERY_BUDGET_SECONDS", 0.2)

    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(200, json=page(adv("LATE")))

    respx.post(QUERY_URL).mock(side_effect=[httpx.Response(200, json=page(adv("A-1"), token="t1")), slow])

    async with asyncio.timeout(2):
        result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert ids(result) == ["A-1"]
    assert result["truncation_reason"] == "time budget of 0.2s exhausted"


@respx.mock
async def test_later_page_failure_keeps_collected_pages(http):
    mock_pages({None: page(adv("A-1"), token="t1"), "t1": httpx.Response(400)})

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert ids(result) == ["A-1"]
    assert result["truncated"] is True
    assert result["truncation_reason"].startswith("page 2 failed: OSV.dev rejected the request (HTTP 400)")


@respx.mock
async def test_first_page_failure_raises(http):
    mock_pages({None: httpx.Response(400)})

    with pytest.raises(ToolError, match="OSV.dev rejected the request"):
        await OSVClient(http).query_package("linux", "Debian:12", None)


# --- Retry inside pagination ---


@respx.mock
async def test_page_2_rate_limited_then_succeeds(http, sleeps):
    # Page 2 gets 429 once; the shared HTTP helper retries it (sleep is patched by the
    # autouse `sleeps` fixture, so this runs instantly) and pagination carries on.
    route = respx.post(QUERY_URL).mock(
        side_effect=[
            httpx.Response(200, json=page(adv("A-1"), adv("A-2"), token="t1")),
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json=page(adv("B-1"))),
        ]
    )

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert route.call_count == 3
    assert [body.get("page_token") for body in sent_bodies(route)] == [None, "t1", "t1"]  # retry resends t1
    assert sleeps == [2.0]  # Retry-After honored, without real waiting
    assert sorted(ids(result)) == ["A-1", "A-2", "B-1"]  # both pages
    assert (result["pages"], result["found_count"], result["returned_count"]) == (2, 3, 3)
    assert (result["truncated"], result["truncation_reason"]) == (False, None)
    assert "ranking_note" not in result


# --- ranking_note ---

RANKING_NOTE = "Ranking covers only the advisories collected before truncation."


@respx.mock
@pytest.mark.parametrize(
    "pages",
    [
        {None: page(*[adv(f"V-{i:03d}") for i in range(MAX_QUERY_RESULTS + 1)])},  # over the cap
        {None: page(adv("A-1"), token="t1"), "t1": page(adv("B-1"), token="t1")},  # stalled
        {None: page(adv("A-1"), token="t1"), "t1": httpx.Response(400)},  # later page failed
    ],
    ids=["cap", "stall", "page-failure"],
)
async def test_ranking_note_present_when_truncated(http, pages):
    mock_pages(pages)

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert result["truncated"] is True
    assert result["ranking_note"] == RANKING_NOTE


@respx.mock
@pytest.mark.parametrize(
    "pages",
    [
        {None: page()},  # nothing found
        {None: page(*[adv(f"V-{i:03d}") for i in range(MAX_QUERY_RESULTS)])},  # exactly at the cap
        {None: page(adv("A-1"), token="t1"), "t1": page(adv("B-1"))},  # complete multi-page
    ],
    ids=["empty", "exactly-cap", "multi-page"],
)
async def test_ranking_note_absent_when_not_truncated(http, pages):
    mock_pages(pages)

    result = await OSVClient(http).query_package("linux", "Debian:12", None)

    assert result["truncated"] is False
    assert "ranking_note" not in result
    assert result["found_count"] == result["returned_count"]


@respx.mock
async def test_ranking_note_and_counts_through_the_tool():
    mock_pages({None: page(*[adv(f"V-{i:03d}") for i in range(MAX_QUERY_RESULTS + 3)])})

    async with Client(mcp) as client:
        result = (await client.call_tool("find_vulns_for_package", {"name": "django", "ecosystem": "PyPI"})).structured_content

    assert (result["found_count"], result["returned_count"], len(result["vulns"])) == (53, 50, 50)
    assert result["ranking_note"] == RANKING_NOTE
