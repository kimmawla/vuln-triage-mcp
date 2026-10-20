"""FIRST EPSS client. Batches CVE IDs and converts string scores to floats."""

import math
import re
from typing import Any

import httpx

from vuln_triage_mcp.clients._http import request_json

BASE_URL = "https://api.first.org/data/v1/epss"
SERVICE = "FIRST EPSS"

# Keeps the query string well under common URL length limits.
BATCH_SIZE = 50

_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")


class EPSSClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def get_scores(self, cve_ids: list[str]) -> dict[str, dict[str, float]]:
        """Return {cve_id: {"epss": float, "percentile": float}}.

        Non-CVE IDs are skipped. CVEs that EPSS has no score for are absent from the result.
        """
        wanted = list(dict.fromkeys(c for c in cve_ids if _CVE_RE.fullmatch(c)))
        scores: dict[str, dict[str, float]] = {}
        for start in range(0, len(wanted), BATCH_SIZE):
            batch = wanted[start : start + BATCH_SIZE]
            data = await request_json(
                self._http, "GET", BASE_URL, service=SERVICE, params={"cve": ",".join(batch)}
            )
            scores.update(_parse(data, set(batch)))
        return scores


def _parse(data: Any, requested: set[str]) -> dict[str, dict[str, float]]:
    rows = data.get("data") if isinstance(data, dict) else None
    parsed = {}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or row.get("cve") not in requested:
            continue
        epss = _probability(row.get("epss"))
        percentile = _probability(row.get("percentile"))
        if epss is not None and percentile is not None:
            parsed[row["cve"]] = {"epss": epss, "percentile": percentile}
    return parsed


def _probability(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 <= number <= 1.0 else None
