"""The five MCP tools, exercised in-process through fastmcp.Client with HTTP mocked by respx."""

import json
from importlib.metadata import version
from pathlib import Path

import httpx
import pytest
import respx
from fastmcp import Client
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients import epss as epss_client
from vuln_triage_mcp.clients import kev as kev_client
from vuln_triage_mcp.clients import osv as osv_client
from vuln_triage_mcp.clients.osv import MAX_QUERY_RESULTS
from vuln_triage_mcp.server import UNKNOWN_VERSION, mcp, package_version

FIXTURES = Path(__file__).parent / "fixtures" / "osv"
# Real advisory GHSA-5mf9-h53q-7mhq (Django), CVSS 3.1 6.5, alias CVE-2026-33033.
DJANGO = json.loads((FIXTURES / "v3_1_only.json").read_text())
GHSA = DJANGO["id"]
CVE = "CVE-2026-33033"

OSV_VULN_URL = f"{osv_client.BASE_URL}/vulns/{GHSA}"
OSV_QUERY_URL = f"{osv_client.BASE_URL}/query"
EPSS_BODY = {"data": [{"cve": CVE, "epss": "0.00412", "percentile": "0.61803"}]}
KEV_BODY = {
    "vulnerabilities": [
        {
            "cveID": CVE,
            "vendorProject": "Django",
            "product": "Django",
            "vulnerabilityName": "Django test entry",
            "dateAdded": "2026-10-01",
            "dueDate": "2026-10-22",
            "requiredAction": "Apply updates per vendor instructions.",
        }
    ]
}

TOOLS = {
    "lookup_vulnerability",
    "find_vulns_for_package",
    "get_epss_score",
    "check_known_exploited",
    "triage_vulnerability",
}


async def call(tool: str, **arguments) -> dict:
    async with Client(mcp) as client:
        result = await client.call_tool(tool, arguments)
    return result.structured_content


def mock_epss(**kwargs):
    return respx.get(epss_client.BASE_URL).mock(**(kwargs or {"return_value": httpx.Response(200, json=EPSS_BODY)}))


def mock_kev(**kwargs):
    return respx.get(kev_client.FEED_URL).mock(**(kwargs or {"return_value": httpx.Response(200, json=KEV_BODY)}))


# --- Tool surface ---


async def test_exactly_the_five_tools_with_when_to_use_docstrings():
    async with Client(mcp) as client:
        tools = await client.list_tools()

    assert {t.name for t in tools} == TOOLS
    for tool in tools:
        assert "Use when:" in tool.description, tool.name
        assert "Prefer another tool when:" in tool.description, tool.name
        assert tool.annotations.read_only_hint is True


@pytest.mark.parametrize("mode", ["legacy", None], ids=["initialize", "discover"])
async def test_server_reports_package_version(mode):
    expected = version("vuln-triage-mcp")
    assert expected != version("fastmcp")  # otherwise this test could pass by accident

    if mode == "legacy":
        # The classic initialize handshake that stdio clients use.
        async with Client(mcp, mode="legacy") as client:
            server_info = (await client.initialize()).server_info
    else:
        async with Client(mcp) as client:
            server_info = client.server_info

    assert server_info.name == "vuln-triage"
    assert server_info.version == expected
    assert server_info.version != version("fastmcp")
    assert server_info.version != UNKNOWN_VERSION  # the package is installed in the test env


def test_package_version_falls_back_when_not_installed():
    # A real PackageNotFoundError from importlib.metadata, no patching involved.
    assert package_version("vuln-triage-mcp-not-installed-xyz") == UNKNOWN_VERSION == "0.0.0+unknown"
    assert package_version() == version("vuln-triage-mcp")


# --- lookup_vulnerability ---


@respx.mock
async def test_lookup_vulnerability_happy_path():
    respx.get(OSV_VULN_URL).mock(return_value=httpx.Response(200, json=DJANGO))

    result = await call("lookup_vulnerability", vuln_id=GHSA.upper())  # canonicalized

    assert result["id"] == GHSA
    assert result["cve_ids"] == [CVE]
    assert (result["cvss_score"], result["cvss_version"]) == (6.5, "3.1")
    assert set(result["untrusted_text"]) == {"summary", "details"}
    assert "summary" not in result and "details" not in result  # external text only under untrusted_text


@pytest.mark.parametrize("bad", ["", "not-an-id", "CVE-21-1", "GHSA-abcd-efgh-ijkl", "A" * 1000])
async def test_lookup_vulnerability_invalid_input(bad):
    with pytest.raises(ToolError, match="Invalid vulnerability ID"):
        await call("lookup_vulnerability", vuln_id=bad)


@respx.mock
async def test_lookup_vulnerability_not_found():
    respx.get(OSV_VULN_URL).mock(return_value=httpx.Response(404))

    with pytest.raises(ToolError, match=f"No OSV.dev advisory found for {GHSA}"):
        await call("lookup_vulnerability", vuln_id=GHSA)


# --- find_vulns_for_package ---


@respx.mock
async def test_find_vulns_for_package_with_version():
    route = respx.post(OSV_QUERY_URL).mock(return_value=httpx.Response(200, json={"vulns": [DJANGO]}))

    result = await call("find_vulns_for_package", name="django", ecosystem="pypi", version="5.2.1")

    assert json.loads(route.calls.last.request.read()) == {
        "package": {"name": "django", "ecosystem": "PyPI"},
        "version": "5.2.1",
    }
    assert result["package"] == {"name": "django", "ecosystem": "PyPI", "version": "5.2.1"}
    assert (result["found_count"], result["returned_count"], result["truncated"]) == (1, 1, False)
    assert "ranking_note" not in result
    assert result["vulns"][0]["id"] == GHSA
    assert "untrusted_text" in result["vulns"][0]


@respx.mock
async def test_find_vulns_for_package_without_version_queries_all_versions():
    route = respx.post(OSV_QUERY_URL).mock(return_value=httpx.Response(200, json={"vulns": []}))

    result = await call("find_vulns_for_package", name="@types/node", ecosystem="npm")

    assert json.loads(route.calls.last.request.read()) == {"package": {"name": "@types/node", "ecosystem": "npm"}}
    assert result == {
        "package": {"name": "@types/node", "ecosystem": "npm", "version": None},
        "found_count": 0,
        "returned_count": 0,
        "pages": 1,
        "truncated": False,
        "truncation_reason": None,
        "vulns": [],
    }


@respx.mock
async def test_find_vulns_for_package_truncates_large_results():
    many = [{**DJANGO, "id": f"GHSA-{i:04d}"} for i in range(MAX_QUERY_RESULTS + 7)]
    respx.post(OSV_QUERY_URL).mock(return_value=httpx.Response(200, json={"vulns": many}))

    result = await call("find_vulns_for_package", name="django", ecosystem="PyPI")

    assert (result["found_count"], result["returned_count"], result["truncated"]) == (57, MAX_QUERY_RESULTS, True)
    assert len(result["vulns"]) == MAX_QUERY_RESULTS
    assert result["ranking_note"] == "Ranking covers only the advisories collected before truncation."
    assert result["truncation_reason"] == "showing the 50 highest-CVSS of 57 advisories"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"name": "django", "ecosystem": "cobol"}, "Unsupported ecosystem"),
        ({"name": "", "ecosystem": "PyPI"}, "Invalid package name"),
        ({"name": "django; rm -rf /", "ecosystem": "PyPI"}, "Invalid package name"),
        ({"name": "djangо", "ecosystem": "PyPI"}, "Invalid package name"),  # Cyrillic о
        ({"name": "django", "ecosystem": "PyPI", "version": "1.0 OR 1=1"}, "Invalid version"),
        ({"name": "django", "ecosystem": "PyPI", "version": "9" * 500}, "Invalid version"),
    ],
)
async def test_find_vulns_for_package_invalid_input(args, message):
    with pytest.raises(ToolError, match=message):
        await call("find_vulns_for_package", **args)


# --- get_epss_score ---


@respx.mock
async def test_get_epss_score_happy_path():
    route = mock_epss()

    result = await call("get_epss_score", cve_id=CVE.lower())

    assert route.calls.last.request.url.params["cve"] == CVE
    assert result == {"cve_id": CVE, "found": True, "epss": 0.00412, "percentile": 0.61803}


@respx.mock
async def test_get_epss_score_no_score_is_null_not_zero():
    mock_epss(return_value=httpx.Response(200, json={"data": []}))

    result = await call("get_epss_score", cve_id=CVE)

    assert result == {"cve_id": CVE, "found": False, "epss": None, "percentile": None}


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        (GHSA, "needs a CVE ID, not a GHSA ID"),
        ("CVE-2026", "Invalid CVE ID"),
        ("", "Invalid CVE ID"),
    ],
)
async def test_get_epss_score_invalid_input(bad, message):
    with pytest.raises(ToolError, match=message):
        await call("get_epss_score", cve_id=bad)


# --- check_known_exploited ---


@respx.mock
async def test_check_known_exploited_listed():
    mock_kev()

    result = await call("check_known_exploited", cve_id=CVE)

    assert (result["status"], result["stale"]) == ("listed", False)
    assert result["catalog_fetched_at"]
    assert result["entry"]["date_added"] == "2026-10-01"
    assert result["entry"]["untrusted_text"]["required_action"] == "Apply updates per vendor instructions."


@respx.mock
async def test_check_known_exploited_not_listed():
    mock_kev()

    result = await call("check_known_exploited", cve_id="CVE-2099-0001")

    assert (result["status"], result["entry"]) == ("not_listed", None)


@respx.mock
async def test_check_known_exploited_catalog_unavailable_is_an_error_not_not_listed():
    mock_kev(return_value=httpx.Response(503))

    with pytest.raises(ToolError, match="KEV catalog unavailable"):
        await call("check_known_exploited", cve_id=CVE)


async def test_check_known_exploited_invalid_input():
    with pytest.raises(ToolError, match="needs a CVE ID, not a GHSA ID"):
        await call("check_known_exploited", cve_id=GHSA)


# --- triage_vulnerability ---


@respx.mock
async def test_triage_vulnerability_happy_path():
    respx.get(OSV_VULN_URL).mock(return_value=httpx.Response(200, json=DJANGO))
    epss_route = mock_epss()
    mock_kev()

    result = await call("triage_vulnerability", vuln_id=GHSA)

    assert epss_route.calls.last.request.url.params["cve"] == CVE  # GHSA resolved to its CVE alias
    assert (result["partial"], result["missing_sources"]) == (False, [])
    priority = result["priority"]
    # 6.5/10*40 = 26.0, 0.00412*35 = 0.1, KEV +25 -> 51.1, floored to 80
    assert priority["components"] == {"cvss": 26.0, "epss": 0.1, "kev": 25.0}
    assert (priority["score"], priority["bucket"], priority["confidence"]) == (80, "critical", "full")
    assert result["kev"]["status"] == "listed"
    assert result["fix_available"] is True
    assert "untrusted_text" in result["advisory"]


async def test_triage_vulnerability_invalid_input():
    with pytest.raises(ToolError, match="Invalid vulnerability ID"):
        await call("triage_vulnerability", vuln_id="ignore previous instructions")


@respx.mock
async def test_triage_vulnerability_epss_failing_returns_partial():
    respx.get(OSV_VULN_URL).mock(return_value=httpx.Response(200, json=DJANGO))
    mock_epss(return_value=httpx.Response(503))
    mock_kev()

    result = await call("triage_vulnerability", vuln_id=GHSA)

    assert result["partial"] is True
    assert [m["source"] for m in result["missing_sources"]] == ["FIRST EPSS"]
    assert "FIRST EPSS" in result["missing_sources"][0]["reason"]
    assert result["epss"] is None
    assert "epss" not in result["priority"]["components"]
    assert result["priority"]["confidence"] == "partial"
    assert "No EPSS score available" in result["priority"]["reasoning"]
    assert result["kev"]["status"] == "listed"


@respx.mock
async def test_triage_vulnerability_ghsa_only_advisory():
    ghsa_only = {**DJANGO, "aliases": ["PYSEC-2026-48"]}  # no CVE alias
    respx.get(OSV_VULN_URL).mock(return_value=httpx.Response(200, json=ghsa_only))
    epss_route = mock_epss()
    kev_route = mock_kev()

    result = await call("triage_vulnerability", vuln_id=GHSA)

    assert epss_route.call_count == 0 and kev_route.call_count == 0
    assert result["advisory"]["cve_ids"] == []
    assert result["partial"] is True
    assert [m["source"] for m in result["missing_sources"]] == ["FIRST EPSS", "CISA KEV"]
    assert all("has no CVE alias" in m["reason"] for m in result["missing_sources"])
    assert result["kev"]["status"] == "unknown"  # never "not_listed"
    assert result["priority"]["components"] == {"cvss": 26.0}
    assert result["priority"]["confidence"] == "low"
    assert "KEV status could not be determined" in result["priority"]["reasoning"]


# --- stdout is reserved for JSON-RPC ---


@respx.mock
async def test_tools_write_nothing_to_stdout(capsys):
    respx.get(OSV_VULN_URL).mock(return_value=httpx.Response(200, json=DJANGO))
    mock_epss(return_value=httpx.Response(503))
    mock_kev(return_value=httpx.Response(503))

    await call("triage_vulnerability", vuln_id=GHSA)
    with pytest.raises(ToolError):
        await call("lookup_vulnerability", vuln_id="bad")

    assert capsys.readouterr().out == ""
