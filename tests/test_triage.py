import asyncio
import json
from pathlib import Path

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from vuln_triage_mcp import scoring
from vuln_triage_mcp.clients import EPSSClient, KEVClient, OSVClient
from vuln_triage_mcp.clients import epss as epss_client
from vuln_triage_mcp.clients import kev as kev_client
from vuln_triage_mcp.clients import osv as osv_client
from vuln_triage_mcp.clients.kev import KEVStatus
from vuln_triage_mcp.scoring import triage
from vuln_triage_mcp.server import mcp

FIXTURES = Path(__file__).parent / "fixtures" / "osv"
LOG4SHELL = json.loads((FIXTURES / "v2_only.json").read_text())  # GHSA-jfh8-c2jp-5v3q, alias CVE-2021-44228
LOG4SHELL["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]
CVE = "CVE-2021-44228"
GHSA = LOG4SHELL["id"]
CVE_RECORD = {**LOG4SHELL, "id": CVE, "aliases": [GHSA]}

OSV_CVE_URL = f"{osv_client.BASE_URL}/vulns/{CVE}"
OSV_GHSA_URL = f"{osv_client.BASE_URL}/vulns/{GHSA}"
EPSS_BODY = {"data": [{"cve": CVE, "epss": "0.94424", "percentile": "0.99985"}]}
KEV_BODY = {"vulnerabilities": [{"cveID": CVE, "vulnerabilityName": "Log4Shell", "dateAdded": "2021-12-10"}]}


@pytest.fixture
def deps(http):
    return {"osv": OSVClient(http), "epss": EPSSClient(http), "kev": KEVClient(http)}


def mock_all(*, osv=None, epss=None, kev=None):
    osv_route = respx.get(OSV_CVE_URL).mock(**(osv or {"return_value": httpx.Response(200, json=CVE_RECORD)}))
    epss_route = respx.get(epss_client.BASE_URL).mock(**(epss or {"return_value": httpx.Response(200, json=EPSS_BODY)}))
    kev_route = respx.get(kev_client.FEED_URL).mock(**(kev or {"return_value": httpx.Response(200, json=KEV_BODY)}))
    return osv_route, epss_route, kev_route


@respx.mock
async def test_cve_sources_run_concurrently(deps):
    # Each mocked source blocks until all three are in flight; sequential calls would time out.
    barrier = asyncio.Barrier(3)

    def blocking(response):
        async def handler(request):
            async with asyncio.timeout(1):
                await barrier.wait()
            return response

        return handler

    mock_all(
        osv={"side_effect": blocking(httpx.Response(200, json=CVE_RECORD))},
        epss={"side_effect": blocking(httpx.Response(200, json=EPSS_BODY))},
        kev={"side_effect": blocking(httpx.Response(200, json=KEV_BODY))},
    )

    result = await triage(CVE, **deps)

    assert result["partial"] is False
    assert result["missing_sources"] == []
    assert result["epss"] == {"cve_id": CVE, "epss": 0.94424, "percentile": 0.99985}
    assert result["kev"]["status"] is KEVStatus.LISTED
    assert result["kev"]["entries"][0]["cve_id"] == CVE
    assert result["priority"]["components"] == {"cvss": 40.0, "epss": 33.0, "kev": 25.0}
    assert result["priority"]["score"] == 98
    assert result["priority"]["bucket"] == "critical"
    assert result["priority"]["confidence"] == "full"
    assert result["fix_available"] is True


@respx.mock
async def test_epss_failure_returns_partial(deps):
    mock_all(epss={"return_value": httpx.Response(503)})

    result = await triage(CVE, **deps)

    assert result["partial"] is True
    assert result["missing_sources"] == [
        {"source": "FIRST EPSS", "reason": "FIRST EPSS is unavailable (HTTP 503). Try again later."}
    ]
    assert result["epss"] is None
    assert "epss" not in result["priority"]["components"]
    assert result["kev"]["status"] is KEVStatus.LISTED
    assert result["priority"]["score"] == 80


@respx.mock
async def test_kev_failure_returns_partial_with_unknown_status(deps):
    mock_all(kev={"side_effect": httpx.ConnectError("refused")})

    result = await triage(CVE, **deps)

    assert result["partial"] is True
    assert [m["source"] for m in result["missing_sources"]] == ["CISA KEV"]
    assert "KEV catalog unavailable" in result["missing_sources"][0]["reason"]
    assert result["kev"] == {"status": KEVStatus.UNKNOWN, "stale": None, "catalog_fetched_at": None, "entries": []}
    assert "kev" not in result["priority"]["components"]
    assert result["priority"]["confidence"] == "partial"
    assert "KEV status could not be determined" in result["priority"]["reasoning"]
    assert result["epss"] is not None


@respx.mock
async def test_both_enrichment_sources_fail(deps):
    mock_all(epss={"return_value": httpx.Response(500)}, kev={"return_value": httpx.Response(500)})

    result = await triage(CVE, **deps)

    assert [m["source"] for m in result["missing_sources"]] == ["FIRST EPSS", "CISA KEV"]
    assert result["priority"]["components"] == {"cvss": 40.0}
    assert result["priority"]["confidence"] == "low"
    assert result["advisory"]["id"] == CVE


@respx.mock
@pytest.mark.parametrize(
    ("osv_mock", "message"),
    [
        ({"return_value": httpx.Response(503)}, r"OSV.dev is unavailable \(HTTP 503\)"),
        ({"return_value": httpx.Response(500)}, r"OSV.dev is unavailable \(HTTP 500\)"),
        ({"return_value": httpx.Response(429)}, "OSV.dev is rate limiting"),
        ({"return_value": httpx.Response(400)}, r"OSV.dev rejected the request \(HTTP 400\)"),
        ({"side_effect": httpx.ReadTimeout("slow")}, "OSV.dev timed out"),
        ({"side_effect": httpx.ConnectError("refused")}, "OSV.dev is unreachable"),
    ],
    ids=["503", "500", "429", "400", "timeout", "unreachable"],
)
async def test_osv_failure_fails_whole_call(deps, osv_mock, message):
    # Any OSV failure other than a 404 for a CVE still fails the call (see the
    # no-OSV-record tests below for the 404 case).
    mock_all(osv=osv_mock)

    with pytest.raises(ToolError, match=message):
        await triage(CVE, **deps)


# --- CVE with no OSV.dev record (404) ---

NO_RECORD = {"source": "osv", "reason": "no OSV.dev record (common for vendor/closed-source products)"}
NO_SEVERITY = "The score has no severity component, so the bucket reflects exploitation signals (EPSS, KEV) only."


@respx.mock
async def test_ghsa_without_osv_record_still_raises(deps):
    respx.get(OSV_GHSA_URL).mock(return_value=httpx.Response(404))
    _, epss_route, kev_route = mock_all()

    with pytest.raises(ToolError, match=f"No OSV.dev advisory found for {GHSA}"):
        await triage(GHSA, **deps)
    assert epss_route.call_count == 0 and kev_route.call_count == 0


@respx.mock
async def test_malformed_cve_like_id_404_still_raises(deps):
    # triage expects validated IDs; if one slips through, a 404 must not become "no record".
    bad = "CVE-21-1"
    respx.get(f"{osv_client.BASE_URL}/vulns/{bad}").mock(return_value=httpx.Response(404))
    respx.get(epss_client.BASE_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(kev_client.FEED_URL).mock(return_value=httpx.Response(200, json=KEV_BODY))

    with pytest.raises(ToolError, match=f"No OSV.dev advisory found for {bad}"):
        await triage(bad, **deps)


@respx.mock
async def test_cve_without_osv_record_kev_listed_floors_at_80(deps):
    mock_all(osv={"return_value": httpx.Response(404)})  # KEV lists CVE, EPSS 0.94424

    result = await triage(CVE, **deps)

    assert result["advisory"] is None
    assert result["fix_available"] is None
    assert result["missing_sources"] == [NO_RECORD]
    assert result["partial"] is True
    priority = result["priority"]
    assert priority["components"] == {"epss": 33.0, "kev": 25.0}  # no "cvss" key
    assert (priority["score"], priority["bucket"], priority["confidence"]) == (80, "critical", "partial")
    assert "No OSV.dev record (common for vendor/closed-source products), so there is no CVSS score." in priority["reasoning"]
    assert NO_SEVERITY in priority["reasoning"]
    assert "Score raised from 58 to the KEV floor of 80. CISA KEV lists it as exploited in the wild" in priority["reasoning"]
    assert "may not exist" not in priority["reasoning"]


@respx.mock
async def test_cve_without_osv_record_not_in_kev_tiny_epss_is_unknown(deps):
    # Re-ruled: no CVSS + not KEV-listed -> unknown (was "low, partial"). Confidence is
    # still partial (EPSS and KEV answered); the bucket is what changes.
    other = "CVE-2024-12345"
    respx.get(f"{osv_client.BASE_URL}/vulns/{other}").mock(return_value=httpx.Response(404))
    respx.get(epss_client.BASE_URL).mock(
        return_value=httpx.Response(200, json={"data": [{"cve": other, "epss": "0.00210", "percentile": "0.41000"}]})
    )
    respx.get(kev_client.FEED_URL).mock(return_value=httpx.Response(200, json=KEV_BODY))  # lists only Log4Shell

    result = await triage(other, **deps)

    assert result["missing_sources"] == [NO_RECORD]
    assert result["kev"]["status"] is KEVStatus.NOT_LISTED
    priority = result["priority"]
    assert priority["components"] == {"epss": 0.1, "kev": 0.0}
    assert (priority["score"], priority["bucket"], priority["confidence"]) == (0, "unknown", "partial")
    assert "Bucket is unknown: too little data to classify (missing CVSS severity)" in priority["reasoning"]
    assert "This is not a low-risk verdict" in priority["reasoning"]
    assert "No OSV.dev record (common for vendor/closed-source products)" in priority["reasoning"]
    assert NO_SEVERITY in priority["reasoning"]
    assert "Confidence partial: 2 of 3 signals; missing CVSS." in priority["reasoning"]
    assert "may not exist" not in priority["reasoning"]  # EPSS knows it


@respx.mock
async def test_cve_unknown_everywhere_may_not_exist(deps):
    # Well-formed, so validation accepts it, but no source knows it. (A typo that lands on
    # another real CVE, e.g. CVE-2021-4422, can't be detected; it gets that CVE's result.)
    typo = "CVE-2099-0000001"
    respx.get(f"{osv_client.BASE_URL}/vulns/{typo}").mock(return_value=httpx.Response(404))
    respx.get(epss_client.BASE_URL).mock(return_value=httpx.Response(200, json={"data": []}))
    respx.get(kev_client.FEED_URL).mock(return_value=httpx.Response(200, json=KEV_BODY))

    result = await triage(typo, **deps)

    priority = result["priority"]
    assert result["missing_sources"] == [NO_RECORD]  # EPSS answered (no score); not a failure
    assert result["epss"] is None
    # Re-ruled: low confidence + not KEV-listed -> unknown (was "low").
    assert (priority["score"], priority["bucket"], priority["confidence"]) == (0, "unknown", "low")
    assert "too little data to classify (missing CVSS severity, EPSS)" in priority["reasoning"]
    assert priority["components"] == {"kev": 0.0}
    assert "This ID may not exist or may be too new" in priority["reasoning"]
    assert "Check the ID for typos." in priority["reasoning"]
    assert NO_SEVERITY in priority["reasoning"]


@respx.mock
@pytest.mark.parametrize(
    ("epss_mock", "kev_mock", "missing"),
    [
        ({"return_value": httpx.Response(503)}, {"return_value": httpx.Response(200, json={"vulnerabilities": []})}, ["osv", "FIRST EPSS"]),
        ({"return_value": httpx.Response(200, json={"data": []})}, {"return_value": httpx.Response(503)}, ["osv", "CISA KEV"]),
    ],
    ids=["epss-failed", "kev-failed"],
)
async def test_cve_without_osv_record_and_a_failed_source_never_says_may_not_exist(deps, epss_mock, kev_mock, missing):
    # A source that failed proves nothing about whether the ID exists.
    mock_all(osv={"return_value": httpx.Response(404)}, epss=epss_mock, kev=kev_mock)

    result = await triage(CVE, **deps)

    assert [m["source"] for m in result["missing_sources"]] == missing
    assert result["priority"]["confidence"] == "low"
    assert "may not exist" not in result["priority"]["reasoning"]


@respx.mock
async def test_overall_timeout_returns_partial(deps, monkeypatch):
    monkeypatch.setattr(scoring, "TRIAGE_TIMEOUT_SECONDS", 0.2)

    async def hang(request):
        await asyncio.sleep(5)
        return httpx.Response(200, json=EPSS_BODY)

    mock_all(epss={"side_effect": hang})

    async with asyncio.timeout(2):
        result = await triage(CVE, **deps)

    assert result["missing_sources"] == [
        {"source": "FIRST EPSS", "reason": "FIRST EPSS did not respond within the 0.2s triage time limit."}
    ]
    assert result["kev"]["status"] is KEVStatus.LISTED


@respx.mock
async def test_overall_timeout_on_osv_fails_call(deps, monkeypatch):
    monkeypatch.setattr(scoring, "TRIAGE_TIMEOUT_SECONDS", 0.2)

    async def hang(request):
        await asyncio.sleep(5)
        return httpx.Response(200, json=CVE_RECORD)

    mock_all(osv={"side_effect": hang})

    with pytest.raises(ToolError, match="OSV.dev did not respond within the 0.2s"):
        await triage(CVE, **deps)


@respx.mock
async def test_ghsa_queries_epss_and_kev_by_cve_alias(deps):
    respx.get(OSV_GHSA_URL).mock(return_value=httpx.Response(200, json=LOG4SHELL))
    _, epss_route, kev_route = mock_all()

    result = await triage(GHSA, **deps)

    assert epss_route.calls.last.request.url.params["cve"] == CVE
    assert kev_route.call_count == 1
    assert result["partial"] is False
    assert result["kev"]["status"] is KEVStatus.LISTED


@respx.mock
async def test_ghsa_without_cve_alias_marks_enrichment_missing(deps):
    record = {**LOG4SHELL, "aliases": []}
    respx.get(OSV_GHSA_URL).mock(return_value=httpx.Response(200, json=record))
    _, epss_route, kev_route = mock_all()

    result = await triage(GHSA, **deps)

    assert epss_route.call_count == 0 and kev_route.call_count == 0
    assert [m["source"] for m in result["missing_sources"]] == ["FIRST EPSS", "CISA KEV"]
    assert all("no CVE alias" in m["reason"] for m in result["missing_sources"])
    assert result["kev"]["status"] is KEVStatus.UNKNOWN


@respx.mock
async def test_unexpected_enrichment_error_is_partial_and_not_leaked(deps, caplog):
    mock_all()

    async def broken(cve_ids):
        raise RuntimeError("secret internal detail")

    deps["epss"].get_scores = broken

    result = await triage(CVE, **deps)

    assert result["missing_sources"] == [{"source": "FIRST EPSS", "reason": "FIRST EPSS lookup failed unexpectedly."}]
    assert "secret internal detail" not in json.dumps(result, default=str)
    assert any(r.exc_info for r in caplog.records)  # traceback goes to the log, not the result


@respx.mock
async def test_tool_via_mcp_client():
    mock_all(epss={"return_value": httpx.Response(503)})

    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
        assert "triage_vulnerability" in tools

        result = await client.call_tool("triage_vulnerability", {"vuln_id": "cve-2021-44228"})
        assert result.structured_content["partial"] is True
        assert result.structured_content["missing_sources"][0]["source"] == "FIRST EPSS"
        assert result.structured_content["kev"]["status"] == "listed"

        with pytest.raises(ToolError, match="Invalid vulnerability ID"):
            await client.call_tool("triage_vulnerability", {"vuln_id": "not-an-id"})
