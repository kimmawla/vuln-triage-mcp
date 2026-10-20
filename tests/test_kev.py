import asyncio
import logging
from datetime import UTC, datetime

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients._http import (
    MAX_STATUS_RETRIES,
    MAX_TRANSPORT_RETRIES,
)
from vuln_triage_mcp.clients.kev import (
    CACHE_TTL_SECONDS,
    FEED_URL,
    REFRESH_RETRY_SECONDS,
    KEVClient,
    KEVStatus,
)

LOG4SHELL_ENTRY = {
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j2",
    "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
    "dateAdded": "2021-12-10",
    "shortDescription": "Apache Log4j2 contains a vulnerability\u200b where JNDI features do not protect against attacker-controlled JNDI-related endpoints.",
    "requiredAction": "Apply updates per vendor instructions.",
    "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
    "notes": "",
}

FEED = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "vulnerabilities": [LOG4SHELL_ENTRY]}
FETCHED_AT = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
# One failed download attempt against a persistently failing server.
FAILED_ATTEMPT_CALLS = 1 + MAX_STATUS_RETRIES


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def kev(http, clock):
    return KEVClient(http, clock=clock, wall_clock=lambda: FETCHED_AT)


async def slow_feed(request):
    # Holds the download open so concurrent callers pile up behind it.
    await asyncio.sleep(0.01)
    return httpx.Response(200, json=FEED)


async def slow_failure(request):
    await asyncio.sleep(0.01)
    return httpx.Response(503)


@respx.mock
async def test_lookup_listed(kev):
    respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=FEED))

    assert await kev.lookup("CVE-2021-44228") == {
        "cve_id": "CVE-2021-44228",
        "status": KEVStatus.LISTED,
        "catalog_fetched_at": "2026-10-20T12:00:00+00:00",
        "stale": False,
        "entry": {
            "cve_id": "CVE-2021-44228",
            "date_added": "2021-12-10",
            "due_date": "2021-12-24",
            "known_ransomware_campaign_use": "Known",
            "untrusted_text": {
                "vendor_project": "Apache",
                "product": "Log4j2",
                "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
                "short_description": "Apache Log4j2 contains a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints.",
                "required_action": "Apply updates per vendor instructions.",
            },
        },
    }


@respx.mock
async def test_lookup_not_listed(kev):
    respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=FEED))

    result = await kev.lookup("CVE-2099-0001")

    assert result["status"] is KEVStatus.NOT_LISTED
    assert result["entry"] is None
    assert result["stale"] is False
    assert result["catalog_fetched_at"] == "2026-10-20T12:00:00+00:00"


@respx.mock
@pytest.mark.parametrize(
    ("mock", "calls"),
    [
        ({"return_value": httpx.Response(404)}, 1),
        ({"return_value": httpx.Response(503)}, FAILED_ATTEMPT_CALLS),
        ({"side_effect": httpx.ReadTimeout("slow")}, 1 + MAX_TRANSPORT_RETRIES),
        ({"return_value": httpx.Response(200, json={"vulnerabilities": "nope"})}, 1),
    ],
    ids=["404", "503", "timeout", "invalid-shape"],
)
async def test_cold_start_failed_fetch_raises(kev, mock, calls):
    route = respx.get(FEED_URL).mock(**mock)

    with pytest.raises(ToolError, match="KEV catalog unavailable"):
        await kev.lookup("CVE-2021-44228")
    assert route.call_count == calls


@respx.mock
async def test_429_then_success(kev, sleeps):
    route = respx.get(FEED_URL).mock(side_effect=[httpx.Response(429), httpx.Response(200, json=FEED)])

    result = await kev.lookup("CVE-2021-44228")

    assert result["status"] is KEVStatus.LISTED
    assert route.call_count == 2
    assert len(sleeps) == 1


@respx.mock
async def test_feed_cached_until_ttl_expires(kev, clock):
    route = respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=FEED))

    await kev.lookup("CVE-2021-44228")
    clock.now += CACHE_TTL_SECONDS - 1
    await kev.lookup("CVE-2021-44228")
    assert route.call_count == 1

    clock.now += 2
    result = await kev.lookup("CVE-2021-44228")
    assert route.call_count == 2
    assert result["stale"] is False


@respx.mock
async def test_warm_cache_failed_refresh_serves_stale(kev, clock, caplog):
    route = respx.get(FEED_URL).mock(
        side_effect=[httpx.Response(200, json=FEED)] + [httpx.Response(503)] * FAILED_ATTEMPT_CALLS
    )
    await kev.lookup("CVE-2021-44228")
    clock.now += CACHE_TTL_SECONDS + 1

    with caplog.at_level(logging.WARNING, logger="vuln_triage_mcp.clients.kev"):
        listed = await kev.lookup("CVE-2021-44228")
        not_listed = await kev.lookup("CVE-2099-0001")

    assert listed["status"] is KEVStatus.LISTED and listed["stale"] is True
    assert not_listed["status"] is KEVStatus.NOT_LISTED and not_listed["stale"] is True
    assert listed["catalog_fetched_at"] == "2026-10-20T12:00:00+00:00"
    assert route.call_count == 1 + FAILED_ATTEMPT_CALLS  # second lookup did not retry
    assert any("serving stale catalog" in r.message for r in caplog.records if r.levelno == logging.WARNING)


@respx.mock
async def test_refresh_retried_after_cooldown_and_clears_stale(kev, clock):
    route = respx.get(FEED_URL).mock(
        side_effect=[httpx.Response(200, json=FEED)]
        + [httpx.Response(503)] * FAILED_ATTEMPT_CALLS
        + [httpx.Response(200, json=FEED)]
    )
    await kev.lookup("CVE-2021-44228")
    clock.now += CACHE_TTL_SECONDS + 1
    assert (await kev.lookup("CVE-2021-44228"))["stale"] is True

    clock.now += REFRESH_RETRY_SECONDS - 1
    assert (await kev.lookup("CVE-2021-44228"))["stale"] is True
    assert route.call_count == 1 + FAILED_ATTEMPT_CALLS

    clock.now += 2
    assert (await kev.lookup("CVE-2021-44228"))["stale"] is False
    assert route.call_count == 2 + FAILED_ATTEMPT_CALLS


@respx.mock
async def test_concurrent_lookups_at_expiry_download_once(kev, clock):
    route = respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=FEED))
    await kev.lookup("CVE-2021-44228")
    clock.now += CACHE_TTL_SECONDS + 1
    route.mock(side_effect=slow_feed)
    route.reset()

    results = await asyncio.gather(*(kev.lookup("CVE-2021-44228") for _ in range(10)))

    assert route.call_count == 1
    assert all(r["status"] is KEVStatus.LISTED and r["stale"] is False for r in results)


@respx.mock
async def test_concurrent_lookups_at_expiry_with_failed_refresh_download_once(kev, clock):
    route = respx.get(FEED_URL).mock(return_value=httpx.Response(200, json=FEED))
    await kev.lookup("CVE-2021-44228")
    clock.now += CACHE_TTL_SECONDS + 1
    route.mock(side_effect=slow_failure)
    route.reset()

    results = await asyncio.gather(*(kev.lookup("CVE-2021-44228") for _ in range(10)))

    assert route.call_count == FAILED_ATTEMPT_CALLS
    assert all(r["stale"] is True for r in results)


@respx.mock
async def test_concurrent_cold_start_failure_downloads_once(kev):
    route = respx.get(FEED_URL).mock(side_effect=slow_failure)

    results = await asyncio.gather(
        *(kev.lookup("CVE-2021-44228") for _ in range(10)), return_exceptions=True
    )

    assert route.call_count == FAILED_ATTEMPT_CALLS
    assert all(isinstance(r, ToolError) and "KEV catalog unavailable" in str(r) for r in results)
