"""CISA KEV client. Downloads the catalog once and caches it in memory for 6 hours.

Lookups report "listed" or "not_listed" only when a catalog is actually loaded. If no
catalog has ever loaded, lookup raises ToolError; callers must then treat KEV status as
unknown, never as not listed.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import httpx
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients._http import request_json
from vuln_triage_mcp.sanitize import clean_untrusted

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SERVICE = "CISA KEV"
CACHE_TTL_SECONDS = 6 * 60 * 60
# After a failed refresh with a cache present, wait this long before trying again,
# so an outage does not make every lookup pay for a doomed download.
REFRESH_RETRY_SECONDS = 5 * 60

FIELD_MAX_LEN = 200
TEXT_MAX_LEN = 500

logger = logging.getLogger(__name__)


class KEVStatus(StrEnum):
    LISTED = "listed"
    NOT_LISTED = "not_listed"
    UNKNOWN = "unknown"


class KEVClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._http = http
        self._clock = clock
        self._wall_clock = wall_clock
        self._lock = asyncio.Lock()
        self._catalog: dict[str, dict[str, Any]] | None = None
        self._fetched_at = 0.0
        self._fetched_at_wall: datetime | None = None
        self._failed_at: float | None = None
        # Bumped when a download attempt finishes; lets lock waiters reuse a result they queued behind.
        self._completed_attempts = 0

    async def lookup(self, cve_id: str) -> dict[str, Any]:
        """Return the KEV status of a CVE from the loaded catalog.

        Result keys: cve_id, status ("listed" or "not_listed"), catalog_fetched_at (ISO 8601),
        stale (catalog older than the TTL because a refresh failed), and entry (the normalized
        KEV entry when listed, else None). Raises ToolError if no catalog could be loaded.
        """
        catalog = await self._get_catalog()
        entry = catalog.get(cve_id)
        fetched_at = self._fetched_at_wall.isoformat() if self._fetched_at_wall else None
        return {
            "cve_id": cve_id,
            "status": KEVStatus.LISTED if entry is not None else KEVStatus.NOT_LISTED,
            "catalog_fetched_at": fetched_at,
            "stale": self._is_expired(),
            "entry": _normalize(entry) if entry is not None else None,
        }

    def _is_expired(self) -> bool:
        return self._clock() - self._fetched_at >= CACHE_TTL_SECONDS

    def _usable_without_refresh(self) -> bool:
        if self._catalog is None:
            return False
        if not self._is_expired():
            return True
        return self._failed_at is not None and self._clock() - self._failed_at < REFRESH_RETRY_SECONDS

    async def _get_catalog(self) -> dict[str, dict[str, Any]]:
        if self._usable_without_refresh():
            return self._catalog  # type: ignore[return-value]

        attempts_seen = self._completed_attempts
        async with self._lock:
            if self._usable_without_refresh():
                return self._catalog  # type: ignore[return-value]
            if self._completed_attempts != attempts_seen:
                # A download finished (and failed) while we waited; share its outcome instead of retrying.
                return self._cached_or_raise()

            try:
                data = await request_json(self._http, "GET", FEED_URL, service=SERVICE)
                catalog = _index(data)
            except ToolError:
                self._completed_attempts += 1
                self._failed_at = self._clock()
                if self._catalog is not None:
                    logger.warning(
                        "KEV refresh failed; serving stale catalog fetched at %s",
                        self._fetched_at_wall.isoformat() if self._fetched_at_wall else "unknown",
                    )
                return self._cached_or_raise()

            self._completed_attempts += 1
            self._catalog = catalog
            self._fetched_at = self._clock()
            self._fetched_at_wall = self._wall_clock()
            self._failed_at = None
            return catalog

    def _cached_or_raise(self) -> dict[str, dict[str, Any]]:
        if self._catalog is None:
            raise ToolError("KEV catalog unavailable. KEV status is unknown; try again later.")
        return self._catalog


def _index(data: Any) -> dict[str, dict[str, Any]]:
    entries = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise ToolError(f"{SERVICE} returned an invalid response.")
    return {
        entry["cveID"]: entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("cveID"), str)
    }


def _field(entry: dict[str, Any], key: str, max_len: int = FIELD_MAX_LEN) -> str:
    value = entry.get(key)
    return clean_untrusted(value if isinstance(value, str) else None, max_len)


def _normalize(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": _field(entry, "cveID"),
        "date_added": _field(entry, "dateAdded"),
        "due_date": _field(entry, "dueDate"),
        "known_ransomware_campaign_use": _field(entry, "knownRansomwareCampaignUse"),
        "untrusted_text": {
            "vendor_project": _field(entry, "vendorProject"),
            "product": _field(entry, "product"),
            "vulnerability_name": _field(entry, "vulnerabilityName"),
            "short_description": _field(entry, "shortDescription", TEXT_MAX_LEN),
            "required_action": _field(entry, "requiredAction", TEXT_MAX_LEN),
        },
    }
