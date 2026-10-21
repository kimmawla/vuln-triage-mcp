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
async def test_osv_failure_fails_whole_call(deps):
    mock_all(osv={"return_value": httpx.Response(404)})

    with pytest.raises(ToolError, match=f"No OSV.dev advisory found for {CVE}"):
        await triage(CVE, **deps)


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
