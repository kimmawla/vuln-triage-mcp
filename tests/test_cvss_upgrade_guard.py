"""Upgrade guard for the cvss package.

These tests exist to catch cvss upgrades that change how base scores are computed.
clients/cvss_base.base_score relies on non-public cvss attributes for v4.0, and the
dependency is pinned to one minor version in pyproject.toml. Before widening that pin,
upgrade cvss and run this file: every expected value here was checked against the CVSS
specification and NVD, so a failure means the new release behaves differently.
"""

import json
from pathlib import Path

import pytest

from vuln_triage_mcp.clients.cvss_base import base_score
from vuln_triage_mcp.clients.osv import normalize_vuln

FIXTURES = Path(__file__).parent / "fixtures" / "osv"

V4_BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
V31_BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def test_v4_e_u_scores_base_value():
    # With E:U the threat-adjusted score is 2.7; the base score is 6.9.
    assert base_score(V4_BASE + "/E:U") == 6.9

    # Same vector via the real OSV fixture (GHSA-2mcm-79hx-8fxw), end to end.
    result = normalize_vuln(json.loads((FIXTURES / "v4_0_only.json").read_text()))
    assert (result["cvss_score"], result["cvss_metric_group"]) == (6.9, "base")
    assert result["cvss_vector"] == V4_BASE + "/E:U"  # full vector kept as published


@pytest.mark.parametrize(
    "suffix",
    ["/E:U", "/E:A", "/E:A/CR:H/IR:H/AR:H/MAV:L/MAC:H", "/S:P/AU:Y/R:U/V:C/RE:H/U:Red"],
    ids=["threat-unreported", "threat-attacked", "threat+environmental", "supplemental"],
)
def test_v4_non_base_metrics_ignored(suffix):
    assert base_score(V4_BASE + suffix) == base_score(V4_BASE) == 6.9


@pytest.mark.parametrize(
    "suffix",
    ["/E:U/RL:O/RC:U", "/E:H/RL:W/RC:C", "/E:U/RL:O/RC:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MPR:H"],
    ids=["temporal-low", "temporal-high", "temporal+environmental"],
)
def test_v3_1_temporal_metrics_equal_base_only(suffix):
    assert base_score(V31_BASE + suffix) == base_score(V31_BASE)


@pytest.mark.parametrize(
    "vector",
    [
        V31_BASE,  # NVD's CVSS v3.1 vector for CVE-2021-44228
        V31_BASE + "/E:H",  # as published in GHSA-jfh8-c2jp-5v3q
    ],
    ids=["nvd", "ghsa"],
)
def test_cve_2021_44228_v3_1_scores_10(vector):
    assert base_score(vector) == 10.0


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        (V4_BASE, 6.9),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 6.5),
        ("AV:N/AC:M/Au:N/C:C/I:C/A:C", 9.3),
        ("AV:N/AC:M/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC", 9.3),  # v2 temporal ignored
    ],
)
def test_reference_base_scores(vector, expected):
    assert base_score(vector) == expected
