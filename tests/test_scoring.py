import itertools

import httpx
import pytest
import respx

from vuln_triage_mcp.clients.kev import FEED_URL, KEVClient, KEVStatus
from vuln_triage_mcp.scoring import (
    KEV_FLOOR,
    Bucket,
    Confidence,
    KEVInput,
    PriorityScore,
    fix_available,
    resolve_kev,
    score_vulnerability,
)

FETCHED = "2026-10-20T12:00:00+00:00"
LISTED = KEVInput(KEVStatus.LISTED, stale=False, catalog_fetched_at=FETCHED)
LISTED_STALE = KEVInput(KEVStatus.LISTED, stale=True, catalog_fetched_at=FETCHED)
NOT_LISTED = KEVInput(KEVStatus.NOT_LISTED, stale=False, catalog_fetched_at=FETCHED)
NOT_LISTED_STALE = KEVInput(KEVStatus.NOT_LISTED, stale=True, catalog_fetched_at=FETCHED)
UNKNOWN = KEVInput.unknown()
ALL_KEV = [LISTED, LISTED_STALE, NOT_LISTED, NOT_LISTED_STALE, UNKNOWN]

CVSS_GRID = [x / 2 for x in range(21)]  # 0.0, 0.5, ..., 10.0
EPSS_GRID = [0.0, 0.0001, 0.001, 0.01, 0.05, 0.1, 0.2, 0.33, 0.5, 0.75, 0.9, 0.97, 1.0]
CVSS_VARIANTS = [("3.1", "vector"), ("2.0", "vector"), (None, "ghsa_label")]


def score(cvss=5.0, epss=0.1, kev=NOT_LISTED, version="3.1", source="vector") -> PriorityScore:
    if cvss is None:
        version = source = None
    return score_vulnerability(cvss_score=cvss, cvss_version=version, cvss_source=source, epss=epss, kev=kev)


# --- Spec weights and output shape ---


def test_full_signal_weights_and_output():
    result = score(cvss=7.5, epss=0.2, kev=NOT_LISTED)

    assert result == PriorityScore(
        score=37,  # 30 + 7 + 0
        bucket=Bucket.LOW,
        components={"cvss": 30.0, "epss": 7.0, "kev": 0.0},
        confidence=Confidence.FULL,
        reasoning=result.reasoning,
    )


def test_kev_listed_adds_25_above_floor():
    result = score(cvss=10.0, epss=0.9, kev=LISTED)

    assert result.components == {"cvss": 40.0, "epss": 31.5, "kev": 25.0}
    assert result.score == 97
    assert result.bucket is Bucket.CRITICAL
    assert "Score raised" not in result.reasoning


def test_max_score_is_100():
    assert score(cvss=10.0, epss=1.0, kev=LISTED).score == 100


@pytest.mark.parametrize(
    ("cvss", "epss", "expected_score", "expected_bucket"),
    [
        (10.0, 1.0, 75, Bucket.HIGH),  # 40 + 35
        (10.0, 0.58, 60, Bucket.HIGH),  # 40 + 20.3 = 60.3
        (10.0, 0.56, 60, Bucket.HIGH),  # 40 + 19.6 = 59.6 rounds up
        (10.0, 0.55, 59, Bucket.MEDIUM),  # 40 + 19.2 = 59.2
        (10.0, 0.0, 40, Bucket.MEDIUM),
        (9.9, 0.0, 40, Bucket.MEDIUM),  # 39.6 rounds up
        (9.8, 0.0, 39, Bucket.LOW),  # 39.2
        (0.0, 0.0, 0, Bucket.LOW),
    ],
)
def test_bucket_boundaries(cvss, epss, expected_score, expected_bucket):
    result = score(cvss=cvss, epss=epss, kev=NOT_LISTED)
    assert (result.score, result.bucket) == (expected_score, expected_bucket)


# --- Monotonic in each input ---


@pytest.mark.parametrize("kev", ALL_KEV, ids=lambda k: f"{k.status}-stale{k.stale}")
@pytest.mark.parametrize("epss", [None, 0.0, 0.3, 1.0])
@pytest.mark.parametrize(("version", "source"), CVSS_VARIANTS)
def test_monotonic_in_cvss(kev, epss, version, source):
    scores = [score(cvss=c, epss=epss, kev=kev, version=version, source=source).score for c in CVSS_GRID]
    assert scores == sorted(scores)


@pytest.mark.parametrize("kev", ALL_KEV, ids=lambda k: f"{k.status}-stale{k.stale}")
@pytest.mark.parametrize("cvss", [None, 0.0, 4.3, 7.5, 10.0])
def test_monotonic_in_epss(kev, cvss):
    scores = [score(cvss=cvss, epss=e, kev=kev).score for e in EPSS_GRID]
    assert scores == sorted(scores)


@pytest.mark.parametrize(("cvss", "epss"), list(itertools.product([None, *CVSS_GRID], [None, *EPSS_GRID])))
def test_monotonic_in_kev(cvss, epss):
    not_listed = score(cvss=cvss, epss=epss, kev=NOT_LISTED).score
    listed = score(cvss=cvss, epss=epss, kev=LISTED).score
    unknown = score(cvss=cvss, epss=epss, kev=UNKNOWN).score

    assert listed >= not_listed
    assert listed >= unknown
    # Unknown adds no points, but it does not subtract any either.
    assert unknown == not_listed


def test_bucket_monotonic_with_score():
    order = [Bucket.LOW, Bucket.MEDIUM, Bucket.HIGH, Bucket.CRITICAL]
    results = sorted(
        (score(cvss=c, epss=e, kev=k) for c in CVSS_GRID for e in EPSS_GRID for k in (NOT_LISTED, LISTED)),
        key=lambda r: r.score,
    )
    ranks = [order.index(r.bucket) for r in results]
    assert ranks == sorted(ranks)


# --- KEV floor always holds ---


@pytest.mark.parametrize("kev", [LISTED, LISTED_STALE], ids=["fresh", "stale"])
@pytest.mark.parametrize(("version", "source"), CVSS_VARIANTS)
def test_kev_floor_always_holds(kev, version, source):
    for cvss, epss in itertools.product([None, *CVSS_GRID], [None, *EPSS_GRID]):
        result = score(cvss=cvss, epss=epss, kev=kev, version=version, source=source)
        assert result.score >= KEV_FLOOR == 80, (cvss, epss)
        assert result.bucket is Bucket.CRITICAL


@pytest.mark.parametrize("kev", [LISTED, LISTED_STALE], ids=["fresh", "stale"])
def test_kev_floor_reasoning(kev):
    result = score(cvss=2.0, epss=0.05, kev=kev)  # 8 + 1.8 + 25 = 34.8 -> 35

    assert result.score == 80
    assert result.components["kev"] == 25.0
    assert "Score raised from 35 to the KEV floor of 80." in result.reasoning


def test_kev_floor_with_no_other_signals():
    result = score(cvss=None, epss=None, kev=LISTED_STALE)

    assert result.score == 80
    assert result.components == {"kev": 25.0}
    assert result.confidence is Confidence.LOW


# --- Missing inputs: reasoning and confidence ---

MISSING_CASES = [
    # (cvss, epss, kev, expected confidence, missing names)
    (7.5, 0.2, NOT_LISTED, Confidence.FULL, []),
    (None, 0.2, NOT_LISTED, Confidence.PARTIAL, ["CVSS"]),
    (7.5, None, NOT_LISTED, Confidence.PARTIAL, ["EPSS"]),
    (7.5, 0.2, UNKNOWN, Confidence.PARTIAL, ["KEV"]),
    (None, None, NOT_LISTED, Confidence.LOW, ["CVSS", "EPSS"]),
    (None, 0.2, UNKNOWN, Confidence.LOW, ["CVSS", "KEV"]),
    (7.5, None, UNKNOWN, Confidence.LOW, ["EPSS", "KEV"]),
    (None, None, UNKNOWN, Confidence.LOW, ["CVSS", "EPSS", "KEV"]),
]
MISSING_REASON = {
    "CVSS": "No CVSS score available; CVSS component omitted.",
    "EPSS": "No EPSS score available; EPSS component omitted.",
    "KEV": "KEV status could not be determined",
}
COMPONENT_KEY = {"CVSS": "cvss", "EPSS": "epss", "KEV": "kev"}


@pytest.mark.parametrize(("cvss", "epss", "kev", "confidence", "missing"), MISSING_CASES)
def test_missing_inputs(cvss, epss, kev, confidence, missing):
    result = score(cvss=cvss, epss=epss, kev=kev)

    assert result.confidence is confidence
    for name in ("CVSS", "EPSS", "KEV"):
        if name in missing:
            assert COMPONENT_KEY[name] not in result.components  # omitted, never 0
            assert MISSING_REASON[name] in result.reasoning
        else:
            assert COMPONENT_KEY[name] in result.components
            assert MISSING_REASON[name] not in result.reasoning
    if missing:
        assert f"missing {', '.join(missing)}." in result.reasoning
    else:
        assert "all 3 signals available" in result.reasoning


def test_all_missing_scores_zero_with_low_confidence():
    result = score(cvss=None, epss=None, kev=UNKNOWN)

    assert result.components == {}
    assert result.score == 0
    assert result.confidence is Confidence.LOW


def test_zero_valued_signals_count_as_present():
    result = score(cvss=0.0, epss=0.0, kev=NOT_LISTED)

    assert result.components == {"cvss": 0.0, "epss": 0.0, "kev": 0.0}
    assert result.confidence is Confidence.FULL


def test_ghsa_label_counts_as_a_signal_and_is_flagged():
    result = score(cvss=7.5, version=None, source="ghsa_label")

    assert result.confidence is Confidence.FULL
    assert "approximate" in result.reasoning


def test_v2_flagged_as_older_scale():
    assert "older CVSS v2 scale" in score(cvss=9.3, version="2.0").reasoning


# --- KEV staleness and three-valued status ---


@pytest.mark.parametrize("kev", [LISTED_STALE, NOT_LISTED_STALE], ids=["listed", "not-listed"])
def test_stale_kev_scores_normally_with_note(kev):
    fresh = LISTED if kev.status is KEVStatus.LISTED else NOT_LISTED
    stale_result = score(cvss=6.0, epss=0.3, kev=kev)
    fresh_result = score(cvss=6.0, epss=0.3, kev=fresh)

    assert stale_result.score == fresh_result.score
    assert stale_result.components == fresh_result.components
    assert stale_result.confidence == fresh_result.confidence
    assert f"KEV data is stale (catalog fetched at {FETCHED}" in stale_result.reasoning
    assert "stale" not in fresh_result.reasoning


def test_kev_unknown_differs_from_not_listed():
    unknown = score(kev=UNKNOWN)
    not_listed = score(kev=NOT_LISTED)

    assert not_listed.components["kev"] == 0.0
    assert "kev" not in unknown.components
    assert "Not listed in CISA KEV" in not_listed.reasoning
    assert "Not listed" not in unknown.reasoning
    assert (unknown.confidence, not_listed.confidence) == (Confidence.PARTIAL, Confidence.FULL)


def test_kev_input_cannot_be_used_as_bool():
    with pytest.raises(TypeError, match="three-valued"):
        bool(UNKNOWN)
    with pytest.raises(TypeError):
        if NOT_LISTED:
            pass


# --- fix_available is separate from the score ---


@pytest.mark.parametrize(
    ("fixed_versions", "expected"),
    [
        ([{"ecosystem": "PyPI", "name": "a", "fixed": ["1.2"]}], True),
        ([{"ecosystem": "PyPI", "name": "a", "fixed": []}, {"ecosystem": "PyPI", "name": "b", "fixed": ["2.0"]}], True),
        ([{"ecosystem": "PyPI", "name": "a", "fixed": []}], False),
        ([], None),
    ],
)
def test_fix_available(fixed_versions, expected):
    assert fix_available({"fixed_versions": fixed_versions}) is expected


def test_fix_available_is_not_a_scoring_input():
    with pytest.raises(TypeError):
        score_vulnerability(
            cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss=0.1, kev=NOT_LISTED, fix_available=True
        )


# --- Input validation ---


@pytest.mark.parametrize(("cvss", "epss"), [(-1.0, 0.5), (10.1, 0.5), (5.0, -0.1), (5.0, 1.1)])
def test_out_of_range_inputs_rejected(cvss, epss):
    with pytest.raises(ValueError):
        score(cvss=cvss, epss=epss)


def test_from_lookup_requires_known_status_and_bool_stale():
    with pytest.raises(ValueError):
        KEVInput.from_lookup({"status": "unknown", "stale": False})
    with pytest.raises(TypeError):
        KEVInput.from_lookup({"status": "not_listed"})
    with pytest.raises(TypeError):
        KEVInput.from_lookup({"status": "not_listed", "stale": None})


# --- resolve_kev ---


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


# --- No OSV record / no severity component ---

NO_SEVERITY = "The score has no severity component, so the bucket reflects exploitation signals (EPSS, KEV) only."


@pytest.mark.parametrize("osv_record", [True, False], ids=["osv-record-without-cvss", "no-osv-record"])
def test_missing_cvss_says_no_severity_component(osv_record):
    result = score_vulnerability(
        cvss_score=None, cvss_version=None, cvss_source=None, epss=0.3, kev=NOT_LISTED, osv_record=osv_record
    )

    assert "No CVSS score available; CVSS component omitted." in result.reasoning
    assert NO_SEVERITY in result.reasoning
    assert ("No OSV.dev record" in result.reasoning) is (not osv_record)
    assert "cvss" not in result.components


def test_no_osv_record_kev_listed_floors_at_80_and_says_why():
    result = score_vulnerability(
        cvss_score=None, cvss_version=None, cvss_source=None, epss=0.05, kev=LISTED_STALE, osv_record=False
    )

    assert (result.score, result.bucket) == (80, Bucket.CRITICAL)
    assert "Score raised from 27 to the KEV floor of 80. CISA KEV lists it as exploited in the wild" in result.reasoning
    assert NO_SEVERITY in result.reasoning
    assert "KEV data is stale" in result.reasoning  # stale still floors, with the note


def test_id_may_not_exist_reasoning_and_low_confidence():
    result = score_vulnerability(
        cvss_score=None, cvss_version=None, cvss_source=None, epss=None, kev=NOT_LISTED,
        osv_record=False, id_may_not_exist=True,
    )

    assert result.confidence is Confidence.LOW
    assert "This ID may not exist or may be too new" in result.reasoning


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cvss_score": 5.0, "cvss_version": "3.1", "cvss_source": "vector", "epss": None, "kev": NOT_LISTED, "osv_record": False},
        {"cvss_score": None, "cvss_version": None, "cvss_source": None, "epss": None, "kev": NOT_LISTED, "id_may_not_exist": True},
        {"cvss_score": None, "cvss_version": None, "cvss_source": None, "epss": 0.1, "kev": NOT_LISTED, "osv_record": False, "id_may_not_exist": True},
        {"cvss_score": None, "cvss_version": None, "cvss_source": None, "epss": None, "kev": LISTED, "osv_record": False, "id_may_not_exist": True},
        {"cvss_score": None, "cvss_version": None, "cvss_source": None, "epss": None, "kev": UNKNOWN, "osv_record": False, "id_may_not_exist": True},
    ],
    ids=["cvss-without-osv-record", "may-not-exist-but-osv-record", "may-not-exist-but-epss", "may-not-exist-but-kev-listed", "may-not-exist-but-kev-unknown"],
)
def test_inconsistent_osv_flags_rejected(kwargs):
    with pytest.raises(ValueError):
        score_vulnerability(**kwargs)


def test_kev_unknown_reasoning_names_the_cause():
    default = score_vulnerability(cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss=0.1, kev=UNKNOWN)
    no_alias = score_vulnerability(
        cvss_score=5.0, cvss_version="3.1", cvss_source="vector", epss=0.1, kev=KEVInput.unknown("no CVE alias to look up")
    )

    assert "KEV status could not be determined (catalog unavailable)" in default.reasoning
    assert "KEV status could not be determined (no CVE alias to look up)" in no_alias.reasoning
    assert "catalog unavailable" not in no_alias.reasoning


# --- unknown bucket: no CVSS or low confidence, and not KEV-listed ---

UNKNOWN_EXPLAINED = "too little data to classify"
NOT_A_VERDICT = "This is not a low-risk verdict"


def test_no_cvss_tiny_epss_not_listed_is_unknown():
    result = score(cvss=None, epss=0.002, kev=NOT_LISTED)

    assert result.bucket is Bucket.UNKNOWN
    assert result.confidence is Confidence.PARTIAL  # EPSS and KEV answered
    assert result.score == 0  # the number is still returned
    assert "Bucket is unknown: too little data to classify (missing CVSS severity)" in result.reasoning
    assert NOT_A_VERDICT in result.reasoning


@pytest.mark.parametrize("kev", [LISTED, LISTED_STALE], ids=["fresh", "stale"])
@pytest.mark.parametrize("epss", [None, 0.0, 0.002])
def test_no_cvss_kev_listed_is_critical(kev, epss):
    result = score(cvss=None, epss=epss, kev=kev)

    assert (result.score, result.bucket) == (80, Bucket.CRITICAL)
    assert UNKNOWN_EXPLAINED not in result.reasoning


def test_cvss_present_epss_missing_not_listed_low_cvss_is_computed():
    # The earlier "partial confidence + low score -> low" case, kept for CVSS present.
    result = score(cvss=3.1, epss=None, kev=NOT_LISTED)

    assert (result.score, result.bucket, result.confidence) == (12, Bucket.LOW, Confidence.PARTIAL)
    assert UNKNOWN_EXPLAINED not in result.reasoning


@pytest.mark.parametrize(
    ("cvss", "epss", "kev", "gaps"),
    [
        (7.5, None, UNKNOWN, "EPSS, KEV status"),  # CVSS present: rule (a) alone
        (None, 0.4, UNKNOWN, "CVSS severity, KEV status"),
        (None, None, NOT_LISTED, "CVSS severity, EPSS"),
        (None, None, UNKNOWN, "CVSS severity, EPSS, KEV status"),
    ],
)
def test_low_confidence_not_listed_is_unknown(cvss, epss, kev, gaps):
    result = score(cvss=cvss, epss=epss, kev=kev)

    assert result.confidence is Confidence.LOW
    assert result.bucket is Bucket.UNKNOWN
    assert f"too little data to classify (missing {gaps})" in result.reasoning
    assert NOT_A_VERDICT in result.reasoning


@pytest.mark.parametrize("kev", [NOT_LISTED, NOT_LISTED_STALE], ids=["fresh", "stale"])
def test_full_confidence_unaffected(kev):
    for cvss, epss in itertools.product(CVSS_GRID, EPSS_GRID):
        result = score(cvss=cvss, epss=epss, kev=kev)
        assert result.confidence is Confidence.FULL
        assert result.bucket is not Bucket.UNKNOWN, (cvss, epss)
        assert UNKNOWN_EXPLAINED not in result.reasoning


def test_stale_not_listed_still_counts_as_not_listed():
    stale = score(cvss=None, epss=0.002, kev=NOT_LISTED_STALE)
    fresh = score(cvss=None, epss=0.002, kev=NOT_LISTED)

    assert stale.bucket is fresh.bucket is Bucket.UNKNOWN
    assert stale.score == fresh.score
    assert f"KEV data is stale (catalog fetched at {FETCHED}" in stale.reasoning
    assert "stale" not in fresh.reasoning


@pytest.mark.parametrize(("cvss", "epss"), list(itertools.product([None, 0.0, 5.0, 10.0], [None, 0.0, 0.5])))
@pytest.mark.parametrize("kev", ALL_KEV, ids=lambda k: f"{k.status}-stale{k.stale}")
def test_unknown_iff_not_listed_and_low_confidence_or_no_cvss(cvss, epss, kev):
    result = score(cvss=cvss, epss=epss, kev=kev)
    expected_unknown = kev.status is not KEVStatus.LISTED and (result.confidence is Confidence.LOW or cvss is None)

    assert (result.bucket is Bucket.UNKNOWN) is expected_unknown
    assert (UNKNOWN_EXPLAINED in result.reasoning) is expected_unknown
    if kev.status is KEVStatus.LISTED:
        assert result.bucket is Bucket.CRITICAL
