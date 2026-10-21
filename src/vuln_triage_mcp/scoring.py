"""Priority scoring: combines CVSS, EPSS, and CISA KEV into a 0-100 score with reasoning.

KEV status is three-valued. UNKNOWN (catalog could not be loaded) is never treated as
"not listed": the KEV component is omitted and the reasoning says why.

triage() fetches all three sources concurrently under one deadline. OSV is required;
EPSS and KEV are enrichment, and their failure yields a partial result naming the source.
"""

import asyncio
import logging
from collections.abc import Awaitable, Mapping
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients import epss as epss_client
from vuln_triage_mcp.clients import kev as kev_client
from vuln_triage_mcp.clients import osv as osv_client
from vuln_triage_mcp.clients.epss import EPSSClient
from vuln_triage_mcp.clients.kev import KEVClient, KEVStatus
from vuln_triage_mcp.clients.osv import CVSSSource, OSVClient

logger = logging.getLogger(__name__)

# Wall-clock limit for one triage call across all sources. A GHSA input runs OSV first
# (to learn its CVE IDs) and then EPSS/KEV, so this covers two sequential phases.
TRIAGE_TIMEOUT_SECONDS = 25.0

# Weights per docs/scoring-spec.md. Maximum total is 40 + 35 + 25 = 100.
CVSS_WEIGHT = 40.0
EPSS_WEIGHT = 35.0
KEV_BONUS = 25.0
# Known-exploited vulnerabilities never score below this, even on stale KEV data.
KEV_FLOOR = 80
CVSS_VERSIONS = frozenset({"2.0", "3.0", "3.1", "4.0"})


class Bucket(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    LOW = "low"


# Lower bound of each bucket, highest first.
_BUCKETS = ((80, Bucket.CRITICAL), (60, Bucket.HIGH), (40, Bucket.MEDIUM), (0, Bucket.LOW))


@dataclass(frozen=True)
class PriorityScore:
    score: int
    bucket: Bucket
    # Points per available signal; a missing signal has no key rather than 0.
    components: dict[str, float]
    confidence: Confidence
    reasoning: str


@dataclass(frozen=True)
class KEVInput:
    status: KEVStatus
    stale: bool = False
    catalog_fetched_at: str | None = None

    def __bool__(self) -> bool:
        # Guards against `if kev:` silently collapsing UNKNOWN into False.
        raise TypeError("KEVInput is three-valued; compare .status explicitly")

    @classmethod
    def unknown(cls) -> "KEVInput":
        return cls(KEVStatus.UNKNOWN)

    @classmethod
    def from_lookup(cls, result: Mapping[str, Any]) -> "KEVInput":
        """Build from a KEVClient.lookup() result."""
        status = KEVStatus(result["status"])
        if status is KEVStatus.UNKNOWN:
            raise ValueError("KEV lookup results are listed or not_listed only")
        stale = result.get("stale")
        if not isinstance(stale, bool):
            raise TypeError("KEV lookup result is missing a boolean 'stale'")
        return cls(status, stale=stale, catalog_fetched_at=result.get("catalog_fetched_at"))


async def resolve_kev(client: KEVClient, cve_id: str) -> KEVInput:
    """Look up KEV status, mapping an unavailable catalog to UNKNOWN rather than an error."""
    try:
        return KEVInput.from_lookup(await client.lookup(cve_id))
    except ToolError:
        logger.warning("KEV status unknown for %s: catalog unavailable", cve_id)
        return KEVInput.unknown()


def _cvss_reason(score: float, version: str | None, source: CVSSSource, points: float) -> str:
    if source is CVSSSource.GHSA_LABEL:
        return (
            f"No parseable CVSS vector; CVSS {score:.1f} is approximated from the GHSA severity "
            f"label and contributes {points:g} points (approximate)."
        )
    if version == "2.0":
        return (
            f"CVSS 2.0 base score {score:.1f} contributes {points:g} points. This is from the "
            "older CVSS v2 scale, so treat it as approximate; it is not directly comparable "
            "to v3/v4 scores."
        )
    return f"CVSS {version} base score {score:.1f} contributes {points:g} points."


def _bucket(score: int) -> Bucket:
    return next(bucket for floor, bucket in _BUCKETS if score >= floor)


def score_vulnerability(
    *,
    cvss_score: float | None,
    cvss_version: str | None,
    cvss_source: str | None,
    epss: float | None,
    kev: KEVInput,
) -> PriorityScore:
    """Composite 0-100 priority per docs/scoring-spec.md.

    cvss_version and cvss_source come from the OSV client's normalized result; epss is the
    EPSS probability (not the percentile). Missing inputs are omitted from components,
    named in reasoning, and lower confidence; they never count as 0.
    """
    if cvss_score is not None and not 0.0 <= cvss_score <= 10.0:
        raise ValueError("cvss_score must be between 0 and 10")
    if epss is not None and not 0.0 <= epss <= 1.0:
        raise ValueError("epss must be between 0 and 1")

    components: dict[str, float] = {}
    reasons: list[str] = []
    missing: list[str] = []

    if cvss_score is not None:
        source = CVSSSource(cvss_source)
        if source is CVSSSource.VECTOR and cvss_version not in CVSS_VERSIONS:
            raise ValueError(f"cvss_version must be one of {sorted(CVSS_VERSIONS)} for vector scores")
        components["cvss"] = round(cvss_score / 10.0 * CVSS_WEIGHT, 1)
        reasons.append(_cvss_reason(cvss_score, cvss_version, source, components["cvss"]))
    else:
        missing.append("CVSS")
        reasons.append("No CVSS score available; CVSS component omitted.")

    if epss is not None:
        components["epss"] = round(epss * EPSS_WEIGHT, 1)
        reasons.append(f"EPSS probability {epss:.3f} contributes {components['epss']:g} points.")
    else:
        missing.append("EPSS")
        reasons.append("No EPSS score available; EPSS component omitted.")

    if kev.status is KEVStatus.LISTED:
        components["kev"] = KEV_BONUS
        reasons.append(f"Listed in CISA KEV (known exploited) adds {KEV_BONUS:g} points.")
    elif kev.status is KEVStatus.NOT_LISTED:
        components["kev"] = 0.0
        reasons.append("Not listed in CISA KEV.")
    else:
        missing.append("KEV")
        reasons.append(
            "KEV status could not be determined (catalog unavailable), so the KEV component "
            "is omitted. If this CVE is known exploited, the true priority is at least "
            f"{KEV_FLOOR}."
        )

    # Half-up rounding. Re-rounding the sum to 0.1 first strips float noise (59.4999... -> 59.5).
    score = min(int(round(sum(components.values()), 1) + 0.5), 100)
    if kev.status is KEVStatus.LISTED and score < KEV_FLOOR:
        reasons.append(f"Score raised from {score} to the KEV floor of {KEV_FLOOR}.")
        score = KEV_FLOOR

    if kev.stale and kev.status is not KEVStatus.UNKNOWN:
        reasons.append(
            f"Note: KEV data is stale (catalog fetched at {kev.catalog_fetched_at or 'unknown time'}; "
            "refresh failed), so the listing may be out of date."
        )

    signals = 3 - len(missing)
    confidence = Confidence.FULL if signals == 3 else Confidence.PARTIAL if signals == 2 else Confidence.LOW
    if missing:
        reasons.append(f"Confidence {confidence}: {signals} of 3 signals; missing {', '.join(missing)}.")
    else:
        reasons.append(f"Confidence {confidence}: all 3 signals available.")

    return PriorityScore(
        score=score,
        bucket=_bucket(score),
        components=components,
        confidence=confidence,
        reasoning=" ".join(reasons),
    )


def fix_available(advisory: Mapping[str, Any]) -> bool | None:
    """True if any affected package has a fixed version, False if none do, None if OSV lists no packages.

    Reported alongside the score; never an input to it.
    """
    packages = advisory.get("fixed_versions") or []
    if not packages:
        return None
    return any(package["fixed"] for package in packages)


async def _within(deadline: float, awaitable: Awaitable[Any]) -> Any:
    async with asyncio.timeout_at(deadline):
        return await awaitable


def _failure_reason(service: str, exc: BaseException) -> str:
    if isinstance(exc, ToolError):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return f"{service} did not respond within the {TRIAGE_TIMEOUT_SECONDS:g}s triage time limit."
    logger.error("%s lookup failed unexpectedly", service, exc_info=exc)
    return f"{service} lookup failed unexpectedly."


async def _epss_best(client: EPSSClient, cve_ids: list[str]) -> dict[str, Any] | None:
    """Highest EPSS probability across the CVE IDs, or None if EPSS has no score."""
    scores = await client.get_scores(cve_ids)
    if not scores:
        return None
    cve_id, best = max(scores.items(), key=lambda item: item[1]["epss"])
    return {"cve_id": cve_id, **best}


async def _kev_combined(client: KEVClient, cve_ids: list[str]) -> tuple[KEVInput, list[dict[str, Any]]]:
    """KEV status across the CVE IDs: listed if any is listed. Returns (input, listed entries)."""
    results = await asyncio.gather(*(client.lookup(cve_id) for cve_id in cve_ids))
    listed = [r for r in results if r["status"] is KEVStatus.LISTED]
    primary = dict(listed[0] if listed else results[0])
    primary["stale"] = any(r["stale"] for r in results)
    return KEVInput.from_lookup(primary), [r["entry"] for r in listed]


async def triage(
    vuln_id: str, *, osv: OSVClient, epss: EPSSClient, kev: KEVClient
) -> dict[str, Any]:
    """Fetch OSV, EPSS, and KEV concurrently and score the result.

    Expects a validated, canonical CVE or GHSA ID. Raises ToolError only if OSV fails;
    an EPSS or KEV failure (including the overall deadline) is reported in missing_sources.
    """
    deadline = asyncio.get_running_loop().time() + TRIAGE_TIMEOUT_SECONDS
    missing: list[dict[str, str]] = []

    if vuln_id.startswith("CVE-"):
        cve_ids = [vuln_id]
        advisory, epss_result, kev_result = await asyncio.gather(
            _within(deadline, osv.get_vuln(vuln_id)),
            _within(deadline, _epss_best(epss, cve_ids)),
            _within(deadline, _kev_combined(kev, cve_ids)),
            return_exceptions=True,
        )
        if isinstance(advisory, BaseException):
            raise ToolError(_failure_reason(osv_client.SERVICE, advisory))
    else:
        # EPSS and KEV are keyed by CVE, so a GHSA needs its aliases from OSV first.
        try:
            advisory = await _within(deadline, osv.get_vuln(vuln_id))
        except Exception as exc:  # noqa: BLE001 - mapped to a short ToolError, unexpected ones logged
            raise ToolError(_failure_reason(osv_client.SERVICE, exc)) from None
        cve_ids = advisory["cve_ids"]
        if cve_ids:
            epss_result, kev_result = await asyncio.gather(
                _within(deadline, _epss_best(epss, cve_ids)),
                _within(deadline, _kev_combined(kev, cve_ids)),
                return_exceptions=True,
            )
        else:
            no_cve = ToolError(f"{vuln_id} has no CVE alias, so this source could not be queried.")
            epss_result, kev_result = no_cve, no_cve

    if isinstance(epss_result, BaseException):
        missing.append({"source": epss_client.SERVICE, "reason": _failure_reason(epss_client.SERVICE, epss_result)})
        epss_result = None

    if isinstance(kev_result, BaseException):
        missing.append({"source": kev_client.SERVICE, "reason": _failure_reason(kev_client.SERVICE, kev_result)})
        kev_input, kev_entries = KEVInput.unknown(), []
    else:
        kev_input, kev_entries = kev_result

    priority = score_vulnerability(
        cvss_score=advisory["cvss_score"],
        cvss_version=advisory["cvss_version"],
        cvss_source=advisory["cvss_source"],
        epss=epss_result["epss"] if epss_result else None,
        kev=kev_input,
    )
    return {
        "vuln_id": vuln_id,
        "priority": asdict(priority),
        "fix_available": fix_available(advisory),
        "advisory": advisory,
        "epss": epss_result,
        "kev": {
            "status": kev_input.status,
            "stale": kev_input.stale if kev_input.status is not KEVStatus.UNKNOWN else None,
            "catalog_fetched_at": kev_input.catalog_fetched_at,
            "entries": kev_entries,
        },
        "partial": bool(missing),
        "missing_sources": missing,
    }
