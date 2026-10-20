import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients._http import MAX_TRANSPORT_RETRIES, NotFoundError
from vuln_triage_mcp.clients.epss import BASE_URL, BATCH_SIZE, EPSSClient


def epss_response(*rows):
    return httpx.Response(200, json={"status": "OK", "status-code": 200, "data": list(rows)})


LOG4SHELL_ROW = {"cve": "CVE-2021-44228", "epss": "0.944240000", "percentile": "0.999850000", "date": "2026-10-19"}
OTHER_ROW = {"cve": "CVE-2022-22965", "epss": "0.97", "percentile": "0.9998", "date": "2026-10-19"}


@respx.mock
async def test_get_scores_success(http):
    route = respx.get(BASE_URL).mock(return_value=epss_response(LOG4SHELL_ROW, OTHER_ROW))

    scores = await EPSSClient(http).get_scores(["CVE-2021-44228", "CVE-2022-22965", "CVE-2099-0001"])

    assert scores == {
        "CVE-2021-44228": {"epss": 0.94424, "percentile": 0.99985},
        "CVE-2022-22965": {"epss": 0.97, "percentile": 0.9998},
    }
    assert route.call_count == 1
    assert route.calls.last.request.url.params["cve"] == "CVE-2021-44228,CVE-2022-22965,CVE-2099-0001"


@respx.mock
async def test_get_scores_404(http, sleeps):
    route = respx.get(BASE_URL).mock(return_value=httpx.Response(404))

    with pytest.raises(NotFoundError):
        await EPSSClient(http).get_scores(["CVE-2021-44228"])
    assert route.call_count == 1
    assert sleeps == []


@respx.mock
async def test_get_scores_timeout(http, sleeps):
    route = respx.get(BASE_URL).mock(side_effect=httpx.ConnectTimeout("timed out"))

    with pytest.raises(ToolError, match="FIRST EPSS timed out"):
        await EPSSClient(http).get_scores(["CVE-2021-44228"])
    assert route.call_count == 1 + MAX_TRANSPORT_RETRIES
    assert len(sleeps) == MAX_TRANSPORT_RETRIES


@respx.mock
async def test_get_scores_429_then_success(http, sleeps):
    route = respx.get(BASE_URL).mock(side_effect=[httpx.Response(429), epss_response(LOG4SHELL_ROW)])

    scores = await EPSSClient(http).get_scores(["CVE-2021-44228"])

    assert scores["CVE-2021-44228"]["epss"] == pytest.approx(0.94424)
    assert route.call_count == 2
    assert len(sleeps) == 1


@respx.mock
async def test_skips_non_cve_ids_and_empty_input(http):
    route = respx.get(BASE_URL).mock(return_value=epss_response())

    assert await EPSSClient(http).get_scores([]) == {}
    assert await EPSSClient(http).get_scores(["GHSA-jfh8-c2jp-5v3q"]) == {}
    assert route.call_count == 0


@respx.mock
async def test_batches_large_requests(http):
    cves = [f"CVE-2024-{n:04d}" for n in range(1000, 1000 + BATCH_SIZE + 5)]
    route = respx.get(BASE_URL).mock(return_value=epss_response())

    await EPSSClient(http).get_scores(cves)

    assert route.call_count == 2
    assert len(route.calls[0].request.url.params["cve"].split(",")) == BATCH_SIZE
    assert len(route.calls[1].request.url.params["cve"].split(",")) == 5


@respx.mock
async def test_drops_malformed_and_unrequested_rows(http):
    respx.get(BASE_URL).mock(
        return_value=epss_response(
            {"cve": "CVE-2021-44228", "epss": "not-a-number", "percentile": "0.5"},
            {"cve": "CVE-2022-22965", "epss": "1.5", "percentile": "0.5"},
            {"cve": "CVE-2023-0001", "epss": "nan", "percentile": "0.5"},
            {"cve": "CVE-1999-0001", "epss": "0.1", "percentile": "0.2"},
            "garbage",
        )
    )

    scores = await EPSSClient(http).get_scores(["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-0001"])

    assert scores == {}
