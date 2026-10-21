"""OSV.dev client. Returns advisories normalized to a compact, model-friendly dict."""

import asyncio
import logging
import re
from enum import StrEnum
from typing import Any

import httpx
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients._http import NotFoundError, request_json
from vuln_triage_mcp.clients.cvss_base import base_score, vector_version
from vuln_triage_mcp.sanitize import clean_untrusted

logger = logging.getLogger(__name__)

BASE_URL = "https://api.osv.dev/v1"
SERVICE = "OSV.dev"

SUMMARY_MAX_LEN = 300
DETAILS_MAX_LEN = 1500
MAX_REFERENCES = 20
MAX_AFFECTED = 25
MAX_FIXED_PER_PACKAGE = 20
FIELD_MAX_LEN = 200
URL_MAX_LEN = 500

_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")

# POST /v1/query pagination (see docs/api-notes.md). Huge packages (Debian linux) run to
# ~15k advisories over 7 pages at ~10s each, so stop at whichever limit comes first.
MAX_QUERY_PAGES = 5
QUERY_BUDGET_SECONDS = 25.0
# Advisories returned per query, after dedupe and sorting.
MAX_QUERY_RESULTS = 50
PAGINATION_STALLED = "pagination did not advance"
RANKING_NOTE = "Ranking covers only the advisories collected before truncation."


class CVSSSource(StrEnum):
    VECTOR = "vector"
    GHSA_LABEL = "ghsa_label"


# Selection order: v3.x, then v4.0, then v2. The first vector with a usable score wins.
# Each OSV severity type accepts only vectors whose prefix names one of its versions.
_CVSS_TYPES = (
    ("CVSS_V3", frozenset({"3.0", "3.1"})),
    ("CVSS_V4", frozenset({"4.0"})),
    ("CVSS_V2", frozenset({"2.0"})),
)

# Scores always use base metrics only; exploit likelihood comes from EPSS and KEV instead.
CVSS_METRIC_GROUP = "base"

# database_specific.severity values (GHSA uses MODERATE): (approximate score, qualitative label).
_GHSA_LABELS = {
    "CRITICAL": (9.5, "CRITICAL"),
    "HIGH": (7.5, "HIGH"),
    "MODERATE": (5.0, "MEDIUM"),
    "MEDIUM": (5.0, "MEDIUM"),
    "LOW": (2.0, "LOW"),
}


class OSVClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        """Fetch one advisory by OSV, GHSA, or CVE ID. Expects an already-validated ID."""
        try:
            data = await request_json(self._http, "GET", f"{BASE_URL}/vulns/{vuln_id}", service=SERVICE)
        except NotFoundError:
            raise NotFoundError(f"No OSV.dev advisory found for {vuln_id}.") from None
        return normalize_vuln(data)

    async def query_package(
        self, name: str, ecosystem: str, version: str | None, *, limit: int = MAX_QUERY_RESULTS
    ) -> dict[str, Any]:
        """List advisories affecting a package, or one version of it. Expects validated inputs.

        Follows next_page_token for up to MAX_QUERY_PAGES pages within QUERY_BUDGET_SECONDS,
        dedupes by advisory ID, sorts by CVSS (highest first, unscored last, then ID), and
        returns at most `limit`. Returns {"vulns", "found_count", "returned_count", "pages",
        "truncated", "truncation_reason"}, plus "ranking_note" only when truncated.
        found_count counts unique advisories collected, before the cap; returned_count is
        len(vulns).
        A first-page failure raises ToolError; a later-page failure returns what was
        collected with truncated=true.
        """
        query: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if version is not None:
            query["version"] = version

        deadline = asyncio.get_running_loop().time() + QUERY_BUDGET_SECONDS
        by_id: dict[str, dict[str, Any]] = {}
        unnamed: list[dict[str, Any]] = []
        used_tokens: set[str] = set()
        first_ids: set[str] = set()
        token: str | None = None
        pages = 0
        stop_reason: str | None = None

        while True:
            body = query if token is None else {**query, "page_token": token}
            try:
                async with asyncio.timeout_at(deadline):
                    data = await request_json(self._http, "POST", f"{BASE_URL}/query", service=SERVICE, json=body)
            except (TimeoutError, ToolError) as exc:
                if pages == 0:
                    if isinstance(exc, TimeoutError):
                        raise ToolError(f"{SERVICE} query exceeded {QUERY_BUDGET_SECONDS:g}s. Try again later.") from None
                    raise
                stop_reason = (
                    f"time budget of {QUERY_BUDGET_SECONDS:g}s exhausted"
                    if isinstance(exc, TimeoutError)
                    else f"page {pages + 1} failed: {exc}"
                )
                break

            raw = data.get("vulns") if isinstance(data, dict) else None
            page = [normalize_vuln(v) for v in raw or [] if isinstance(v, dict)]
            if page and page[0]["id"] and page[0]["id"] in first_ids:
                stop_reason = PAGINATION_STALLED
                logger.warning(
                    "%s query for %s/%s: page %d repeats a previous page's first advisory %s; stopping",
                    SERVICE, ecosystem, name, pages + 1, page[0]["id"],
                )
                break
            pages += 1
            if page and page[0]["id"]:
                first_ids.add(page[0]["id"])
            for vuln in page:
                if vuln["id"]:
                    by_id.setdefault(vuln["id"], vuln)
                else:
                    unnamed.append(vuln)

            if token is not None:
                used_tokens.add(token)
            next_token = data.get("next_page_token") if isinstance(data, dict) else None
            if not isinstance(next_token, str) or not next_token:
                break
            if next_token in used_tokens:
                stop_reason = PAGINATION_STALLED
                logger.warning(
                    "%s query for %s/%s: page %d returned an already-used page token; stopping",
                    SERVICE, ecosystem, name, pages,
                )
                break
            if pages >= MAX_QUERY_PAGES:
                stop_reason = f"page limit of {MAX_QUERY_PAGES} reached"
                break
            token = next_token

        vulns = sorted([*by_id.values(), *unnamed], key=_cvss_sort_key)
        reasons = [stop_reason] if stop_reason else []
        if len(vulns) > limit:
            reasons.append(f"showing the {limit} highest-CVSS of {len(vulns)} advisories")
        returned = vulns[:limit]
        result: dict[str, Any] = {
            "vulns": returned,
            "found_count": len(vulns),
            "returned_count": len(returned),
            "pages": pages,
            "truncated": bool(reasons),
            "truncation_reason": "; ".join(reasons) or None,
        }
        if reasons:
            result["ranking_note"] = RANKING_NOTE
        return result


def _cvss_sort_key(vuln: dict[str, Any]) -> tuple[bool, float, str]:
    """Highest CVSS first; advisories without a score last; ties by ID for a stable order."""
    score = vuln["cvss_score"]
    return (score is None, -(score or 0.0), vuln["id"])


def normalize_vuln(data: dict[str, Any]) -> dict[str, Any]:
    vuln_id = _clean_field(data.get("id"))
    return {
        "id": vuln_id,
        "cve_ids": _cve_ids(vuln_id, data.get("aliases")),
        **_cvss(vuln_id, data.get("severity"), data.get("database_specific")),
        "fixed_versions": _fixed_versions(data.get("affected")),
        "references": _references(data.get("references")),
        "untrusted_text": {
            "summary": clean_untrusted(_str_or_none(data.get("summary")), SUMMARY_MAX_LEN),
            "details": clean_untrusted(_str_or_none(data.get("details")), DETAILS_MAX_LEN),
        },
    }


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _clean_field(value: object) -> str:
    return clean_untrusted(_str_or_none(value), FIELD_MAX_LEN)


def _cve_ids(vuln_id: str, aliases: object) -> list[str]:
    candidates = [vuln_id, *(aliases if isinstance(aliases, list) else [])]
    seen: dict[str, None] = {}
    for candidate in candidates:
        if isinstance(candidate, str) and _CVE_RE.fullmatch(candidate):
            seen.setdefault(candidate)
    return list(seen)


def _cvss(vuln_id: str, severity: object, database_specific: object) -> dict[str, Any]:
    """Return cvss_score, cvss_version, cvss_vector, cvss_metric_group, cvss_source, and severity_label.

    Tries vectors in _CVSS_PARSERS order, then the GHSA label. Never defaults to a score of 0.
    A vector score is always the base score; cvss_vector keeps the full vector as published.
    """
    parsed = _parse_vector(vuln_id, severity)
    if parsed is not None:
        score, version, vector = parsed
        return {
            "cvss_score": score,
            "cvss_version": version,
            "cvss_vector": vector,
            "cvss_metric_group": CVSS_METRIC_GROUP,
            "cvss_source": CVSSSource.VECTOR,
            "severity_label": _label_from_score(score, version),
        }

    raw_label = database_specific.get("severity") if isinstance(database_specific, dict) else None
    ghsa = _GHSA_LABELS.get(raw_label.strip().upper()) if isinstance(raw_label, str) else None
    if ghsa is not None:
        score, label = ghsa
        return {
            "cvss_score": score,
            "cvss_version": None,
            "cvss_vector": None,
            "cvss_metric_group": None,
            "cvss_source": CVSSSource.GHSA_LABEL,
            "severity_label": label,
        }

    return {
        "cvss_score": None,
        "cvss_version": None,
        "cvss_vector": None,
        "cvss_metric_group": None,
        "cvss_source": None,
        "severity_label": None,
    }


def _parse_vector(vuln_id: str, severity: object) -> tuple[float, str, str] | None:
    entries = [e for e in severity if isinstance(e, dict)] if isinstance(severity, list) else []
    for sev_type, versions in _CVSS_TYPES:
        for entry in entries:
            if entry.get("type") != sev_type:
                continue
            vector = entry.get("score")
            version = vector_version(vector)
            score = base_score(vector) if version in versions else None
            if score is None:
                logger.warning(
                    "%s: unusable %s vector %r; falling back",
                    vuln_id,
                    sev_type,
                    vector[:200] if isinstance(vector, str) else type(vector).__name__,
                )
                continue
            return score, version, vector
    return None


def _label_from_score(score: float, version: str) -> str:
    # CVSS v2 has no Critical or None rating.
    if version == "2.0":
        return "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _fixed_versions(affected: object) -> list[dict[str, Any]]:
    if not isinstance(affected, list):
        return []
    packages = []
    for entry in affected[:MAX_AFFECTED]:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        fixed: dict[str, None] = {}
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed.setdefault(_clean_field(event["fixed"]))
        packages.append(
            {
                "ecosystem": _clean_field(package.get("ecosystem")),
                "name": _clean_field(package.get("name")),
                "fixed": list(fixed)[:MAX_FIXED_PER_PACKAGE],
            }
        )
    return packages


def _references(references: object) -> list[str]:
    if not isinstance(references, list):
        return []
    urls: dict[str, None] = {}
    for ref in references:
        if len(urls) >= MAX_REFERENCES:
            break
        url = ref.get("url") if isinstance(ref, dict) else None
        if (
            isinstance(url, str)
            and len(url) <= URL_MAX_LEN
            and url.startswith(("https://", "http://"))
            and url.isascii()
            and not any(ch.isspace() for ch in url)
        ):
            urls.setdefault(url)
    return list(urls)
