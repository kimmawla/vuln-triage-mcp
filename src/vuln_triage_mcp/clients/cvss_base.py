"""CVSS base scores. The only module that relies on the cvss package's non-public attributes."""

import logging

from cvss import CVSS2, CVSS3, CVSS4, CVSSError

logger = logging.getLogger(__name__)

# The CVSS v4.0 base metric group, per the FIRST v4.0 specification. Used only to verify
# that cvss's METRICS_MANDATORY still means "base metrics" before trusting it.
_V4_BASE_METRICS = frozenset({"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"})
_V3_VERSIONS = frozenset({"3.0", "3.1"})


def vector_version(vector: object) -> str | None:
    """CVSS version named by a vector's prefix ("4.0", "3.1", "3.0"), "2.0" if it has none."""
    if not isinstance(vector, str):
        return None
    if not vector.startswith("CVSS:"):
        return "2.0"
    return vector[len("CVSS:") :].split("/", 1)[0]


def base_score(vector: str) -> float | None:
    """CVSS base score from base metrics only, or None if it cannot be computed.

    Threat, temporal, environmental, and supplemental metrics never affect the result.
    None means "no usable score": the caller falls back to the next vector or the GHSA
    label. This function never returns a threat-adjusted score.

    NON-PUBLIC API: for v4.0 this relies on cvss.constants4.METRICS_MANDATORY and on
    CVSS4(...).metrics, neither of which the cvss package documents. cvss's CVSS4 has no
    base-only score (its single score includes threat and environmental metrics), so v4.0
    is rescored from cvss's own parse of the base metrics. The dependency is pinned to the
    tested minor version in pyproject.toml. Guarded by tests/test_cvss_upgrade_guard.py:
    test_v4_e_u_scores_base_value, test_v4_non_base_metrics_ignored,
    test_v3_1_temporal_metrics_equal_base_only, test_cve_2021_44228_v3_1_scores_10, and
    test_reference_base_scores. The fallback when those attributes disappear or change
    meaning (log a warning, return None) is covered by the test_cvss_api_break_* tests in
    tests/test_cvss.py.
    """
    version = vector_version(vector)
    try:
        if version == "4.0":
            from cvss.constants4 import METRICS_MANDATORY

            if frozenset(METRICS_MANDATORY) != _V4_BASE_METRICS:
                logger.warning(
                    "cvss.constants4.METRICS_MANDATORY no longer matches the CVSS v4.0 base "
                    "metrics; not scoring v4.0 vectors"
                )
                return None
            parsed = CVSS4(vector)
            base_metrics = "/".join(f"{m}:{parsed.metrics[m]}" for m in METRICS_MANDATORY)
            return float(CVSS4(f"CVSS:4.0/{base_metrics}").scores()[0])
        if version in _V3_VERSIONS:
            # scores() is (base, temporal, environmental); base ignores the other groups.
            return float(CVSS3(vector).scores()[0])
        if version == "2.0":
            return float(CVSS2(vector).scores()[0])
        return None
    except CVSSError:
        # Malformed vector; the caller logs it with advisory context.
        return None
    except (AttributeError, ImportError) as exc:
        logger.warning(
            "cvss package API mismatch while scoring a CVSS %s vector (%s: %s); "
            "check the installed cvss version",
            version,
            type(exc).__name__,
            exc,
        )
        return None
    # Third-party parser on untrusted input: any other failure is treated as malformed.
    except Exception:  # noqa: BLE001
        return None
