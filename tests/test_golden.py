"""Golden set: expected priority buckets for well-known CVEs (tests/golden.yaml).

The default test replays recorded OSV/EPSS/KEV responses (tests/fixtures/golden/
recorded.json), so it is deterministic and offline. Re-record with
`uv run python scripts/record_golden_fixtures.py` when golden.yaml or the scoring spec
changes.

The @pytest.mark.live variant runs the same expectations against the real APIs. It is
skipped by default (see addopts in pyproject.toml); run it with `uv run pytest -m live`.
EPSS drifts daily, so a live failure means "re-check this expectation", not necessarily
a bug.
"""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
import respx
import yaml

from vuln_triage_mcp.clients import EPSSClient, KEVClient, OSVClient, _http
from vuln_triage_mcp.clients import epss as epss_client
from vuln_triage_mcp.clients import kev as kev_client
from vuln_triage_mcp.clients import osv as osv_client
from vuln_triage_mcp.scoring import triage

TESTS = Path(__file__).parent
GOLDEN = yaml.safe_load((TESTS / "golden.yaml").read_text())
RECORDED = json.loads((TESTS / "fixtures" / "golden" / "recorded.json").read_text())

LOG4SHELL, LIBWEBP, LODASH = "CVE-2021-44228", "CVE-2023-4863", "CVE-2019-10744"

# Golden CVEs with no OSV record: closed-source products, which OSV (open source only)
# doesn't cover. Triage scores them from EPSS and KEV alone; all are KEV-listed, so they
# must reach critical via the KEV floor, with "osv" named in missing_sources.
NO_OSV_RECORD = {
    "CVE-2017-0144": "EternalBlue (Windows SMBv1)",
    "CVE-2021-34527": "PrintNightmare (Windows)",
    "CVE-2021-26855": "ProxyLogon (Exchange)",
    "CVE-2023-34362": "MOVEit Transfer",
}
OSV_MISSING = {"source": "osv", "reason": "no OSV.dev record (common for vendor/closed-source products)"}


def expected_buckets(entry: dict) -> set[str] | None:
    expected = entry.get("expect_bucket")
    if expected is None:
        return None
    return set(expected) if isinstance(expected, list) else {expected}


def golden_params() -> list:
    return [pytest.param(entry, id=entry["id"]) for entry in GOLDEN]


async def run_triage(http: httpx.AsyncClient, vuln_id: str) -> dict:
    return await triage(vuln_id, osv=OSVClient(http), epss=EPSSClient(http), kev=KEVClient(http))


def assert_expectations(entry: dict, result: dict) -> None:
    """Check expect_bucket and/or expect_confidence; every golden entry must set one."""
    priority = result["priority"]
    buckets = expected_buckets(entry)
    confidence = entry.get("expect_confidence")
    assert buckets or confidence, f"{entry['id']}: golden entry sets neither expect_bucket nor expect_confidence"
    context = f"(score {priority['score']}, bucket {priority['bucket']}, confidence {priority['confidence']}). Reasoning: {priority['reasoning']}"
    if buckets:
        assert priority["bucket"] in buckets, f"{entry['id']}: expected bucket in {sorted(buckets)} {context}"
    if confidence:
        assert priority["confidence"] == confidence, f"{entry['id']}: expected confidence {confidence} {context}"


def expected_missing_sources(vuln_id: str, result: dict) -> list[dict]:
    """What a complete recording should still report as missing for this ID."""
    if vuln_id in NO_OSV_RECORD:
        return [OSV_MISSING]
    if vuln_id.startswith("GHSA-") and not result["advisory"]["cve_ids"]:
        reason = f"{vuln_id} has no CVE alias, so this source could not be queried."
        return [{"source": "FIRST EPSS", "reason": reason}, {"source": "CISA KEV", "reason": reason}]
    return []


def assert_ordering(scores: dict[str, int]) -> None:
    assert scores[LOG4SHELL] > scores[LIBWEBP] > scores[LODASH], scores


# --- Replay of recorded responses ---


@pytest.fixture
def replay():
    """Serve recorded OSV/EPSS/KEV responses; anything unrecorded is a 404 or empty."""

    def osv_handler(request: httpx.Request) -> httpx.Response:
        vuln_id = request.url.path.rsplit("/", 1)[-1]
        record = RECORDED["osv"].get(vuln_id)
        return httpx.Response(200, json=record) if record else httpx.Response(404)

    def epss_handler(request: httpx.Request) -> httpx.Response:
        cves = request.url.params["cve"].split(",")
        return httpx.Response(200, json={"data": [RECORDED["epss"][c] for c in cves if c in RECORDED["epss"]]})

    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith=f"{osv_client.BASE_URL}/vulns/").mock(side_effect=osv_handler)
        mock.get(epss_client.BASE_URL).mock(side_effect=epss_handler)
        mock.get(kev_client.FEED_URL).mock(return_value=httpx.Response(200, json=RECORDED["kev"]))
        yield mock


def test_recording_covers_the_golden_set():
    missing = [e["id"] for e in GOLDEN if e["id"] not in RECORDED["osv"]]
    assert not missing, f"Re-record fixtures (scripts/record_golden_fixtures.py); unrecorded: {missing}"


@pytest.mark.parametrize("entry", golden_params())
async def test_golden_bucket_recorded(entry, http, replay):
    result = await run_triage(http, entry["id"])

    # Recorded data is complete, so only structural gaps may be missing (no OSV record,
    # or a GHSA without a CVE alias), never a failed source.
    assert result["missing_sources"] == expected_missing_sources(entry["id"], result)
    assert_expectations(entry, result)


@pytest.mark.parametrize("vuln_id", sorted(NO_OSV_RECORD))
async def test_no_osv_record_cves_are_critical_via_kev_floor(vuln_id, http, replay):
    priority = (await run_triage(http, vuln_id))["priority"]

    assert priority["bucket"] == "critical"
    assert "cvss" not in priority["components"]
    assert priority["components"]["kev"] == 25.0
    assert "bucket reflects exploitation signals (EPSS, KEV) only" in priority["reasoning"]


async def test_ghsa_without_cve_alias_reasoning_says_epss_and_kev_unavailable(http, replay):
    entry = next(e for e in GOLDEN if e["id"].startswith("GHSA-"))
    priority = (await run_triage(http, entry["id"]))["priority"]

    assert "No EPSS score available; EPSS component omitted." in priority["reasoning"]
    assert "KEV status could not be determined (no CVE alias to look up)" in priority["reasoning"]
    assert "catalog unavailable" not in priority["reasoning"]  # the catalog was fine
    assert "missing EPSS, KEV" in priority["reasoning"]
    assert "Bucket is unknown: too little data to classify (missing EPSS, KEV status)" in priority["reasoning"]
    assert "This is not a low-risk verdict" in priority["reasoning"]


async def test_golden_ordering_recorded(http, replay):
    scores = {cve: (await run_triage(http, cve))["priority"]["score"] for cve in (LOG4SHELL, LIBWEBP, LODASH)}
    assert_ordering(scores)


# --- Live APIs (opt-in: uv run pytest -m live) ---


@pytest.fixture
def real_sleep(monkeypatch):
    # conftest's autouse fixture skips retry sleeps; against real APIs, back off for real.
    monkeypatch.setattr(_http, "_sleep", asyncio.sleep)


@pytest.mark.live
@pytest.mark.parametrize("entry", golden_params())
async def test_golden_bucket_live(entry, http, real_sleep):
    result = await run_triage(http, entry["id"])

    assert_expectations(entry, result)


@pytest.mark.live
async def test_golden_ordering_live(http, real_sleep):
    scores = {cve: (await run_triage(http, cve))["priority"]["score"] for cve in (LOG4SHELL, LIBWEBP, LODASH)}
    assert_ordering(scores)
