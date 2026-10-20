import httpx
import pytest
import respx

from vuln_triage_mcp.clients.kev import FEED_URL, KEVClient, KEVStatus
from vuln_triage_mcp.scoring import (
    KEV_FLOOR,
    KEVInput,
    resolve_kev,
    score_vulnerability,
)

LISTED = KEVInput(KEVStatus.LISTED, stale=False, catalog_fetched_at="2026-10-20T12:00:00+00:00")
LISTED_STALE = KEVInput(KEVStatus.LISTED, stale=True, catalog_fetched_at="2026-10-20T12:00:00+00:00")
NOT_LISTED = KEVInput(KEVStatus.NOT_LISTED, stale=False, catalog_fetched_at="2026-10-20T12:00:00+00:00")
NOT_LISTED_STALE = KEVInput(KEVStatus.NOT_LISTED, stale=True, catalog_fetched_at="2026-10-20T12:00:00+00:00")


def test_kev_unknown_omits_component_and_explains():
    result = score_vulnerability(cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.1, kev=KEVInput.unknown())

    assert "kev_floor" not in result["components"]
    assert result["components"] == {"cvss": 25.0, "epss": 5.0}
    assert result["score"] == 30  # not floored, but not scored as "not listed" either
    assert "KEV status could not be determined" in result["reasoning"]
    assert "Not listed" not in result["reasoning"]


def test_kev_unknown_differs_from_not_listed():
    unknown = score_vulnerability(cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.1, kev=KEVInput.unknown())
    not_listed = score_vulnerability(cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.1, kev=NOT_LISTED)

    assert not_listed["components"]["kev_floor"] == 0
    assert "Not listed in CISA KEV" in not_listed["reasoning"]
    assert unknown["components"] != not_listed["components"]
    assert unknown["reasoning"] != not_listed["reasoning"]


def test_kev_input_cannot_be_used_as_bool():
    with pytest.raises(TypeError, match="three-valued"):
        bool(KEVInput.unknown())
    with pytest.raises(TypeError):
        if NOT_LISTED:
            pass


@pytest.mark.parametrize("kev", [LISTED, LISTED_STALE], ids=["fresh", "stale"])
def test_kev_listed_floors_at_80(kev):
    result = score_vulnerability(cvss_score=2.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.05, kev=kev)

    assert result["score"] == KEV_FLOOR == 80
    assert result["components"]["kev_floor"] == 80
    assert "raised to the 80 floor" in result["reasoning"]


def test_kev_listed_stale_adds_note():
    result = score_vulnerability(cvss_score=2.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.05, kev=LISTED_STALE)

    assert result["score"] == 80
    assert "KEV data is stale" in result["reasoning"]
    assert "2026-10-20T12:00:00+00:00" in result["reasoning"]


def test_kev_listed_fresh_has_no_stale_note():
    result = score_vulnerability(cvss_score=2.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.05, kev=LISTED)
    assert "stale" not in result["reasoning"]


def test_kev_not_listed_stale_scores_normally_with_note():
    result = score_vulnerability(cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.1, kev=NOT_LISTED_STALE)

    assert result["score"] == 30
    assert "KEV data is stale" in result["reasoning"]


def test_kev_listed_above_floor_keeps_higher_score():
    result = score_vulnerability(cvss_score=10.0, cvss_version="3.1", cvss_source="vector", epss_percentile=0.99, kev=LISTED)
    assert result["score"] == 100


def test_missing_cvss_and_epss_are_omitted():
    result = score_vulnerability(cvss_score=None, cvss_version=None, cvss_source=None, epss_percentile=None, kev=NOT_LISTED)

    assert result["components"] == {"kev_floor": 0}
    assert result["score"] == 0
    assert "No CVSS score available" in result["reasoning"]
    assert "No EPSS score available" in result["reasoning"]


@pytest.mark.parametrize(("cvss", "epss"), [(-1.0, 0.5), (10.1, 0.5), (5.0, -0.1), (5.0, 1.1)])
def test_out_of_range_inputs_rejected(cvss, epss):
    with pytest.raises(ValueError):
        score_vulnerability(cvss_score=cvss, cvss_version="3.1", cvss_source="vector", epss_percentile=epss, kev=NOT_LISTED)


def test_from_lookup_requires_known_status_and_bool_stale():
    with pytest.raises(ValueError):
        KEVInput.from_lookup({"status": "unknown", "stale": False})
    with pytest.raises(TypeError):
        KEVInput.from_lookup({"status": "not_listed"})
    with pytest.raises(TypeError):
        KEVInput.from_lookup({"status": "not_listed", "stale": None})


@respx.mock
async def test_resolve_kev_cold_failure_is_unknown(http):
    respx.get(FEED_URL).mock(return_value=httpx.Response(503))

    kev = await resolve_kev(KEVClient(http), "CVE-2021-44228")

    assert kev.status is KEVStatus.UNKNOWN


@respx.mock
async def test_resolve_kev_success(http):
    respx.get(FEED_URL).mock(
        return_value=httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2021-44228"}]})
    )
    client = KEVClient(http)

    listed = await resolve_kev(client, "CVE-2021-44228")
    not_listed = await resolve_kev(client, "CVE-2099-0001")

    assert listed.status is KEVStatus.LISTED and listed.stale is False
    assert listed.catalog_fetched_at is not None
    assert not_listed.status is KEVStatus.NOT_LISTED
