"""Shared httpx plumbing: timeouts, retry with backoff, a total time cap, and ToolError mapping."""

import asyncio
import logging
import random
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from fastmcp.exceptions import ToolError

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 8.0
# Wall-clock cap per client call, including retries and backoff.
TOTAL_TIMEOUT_SECONDS = 15.0
# Retries on 429 and 5xx.
MAX_STATUS_RETRIES = 3
# Retries on timeouts and connection errors.
MAX_TRANSPORT_RETRIES = 1
BACKOFF_BASE_SECONDS = 0.5

# Indirection so tests can skip real sleeps.
_sleep = asyncio.sleep


class NotFoundError(ToolError):
    """The upstream service returned 404."""


def make_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(READ_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS),
        headers={"User-Agent": "vuln-triage-mcp/0.1", "Accept": "application/json"},
    )


def _retry_after_seconds(response: httpx.Response) -> float | None:
    """Parse Retry-After as delta-seconds or an HTTP date."""
    value = response.headers.get("Retry-After", "").strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _backoff(retry: int) -> float:
    return BACKOFF_BASE_SECONDS * 2**retry + random.uniform(0, BACKOFF_BASE_SECONDS)


def _too_slow(service: str) -> ToolError:
    return ToolError(
        f"{service} was too slow to respond (no answer within {TOTAL_TIMEOUT_SECONDS:g}s). "
        "You can retry the request."
    )


async def request_json(
    client: httpx.AsyncClient, method: str, url: str, *, service: str, **kwargs: Any
) -> Any:
    """Send a request and return the decoded JSON body.

    Retries 429/5xx up to MAX_STATUS_RETRIES times (honoring Retry-After) and timeouts or
    connection errors up to MAX_TRANSPORT_RETRIES times. Other 4xx responses are not retried.
    The whole call, retries included, is capped at TOTAL_TIMEOUT_SECONDS.
    All failures surface as ToolError with a short message.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + TOTAL_TIMEOUT_SECONDS
    try:
        async with asyncio.timeout_at(deadline):
            return await _request_with_retries(client, method, url, service, deadline, kwargs)
    except TimeoutError:
        logger.warning("%s %s exceeded %gs total", method, url, TOTAL_TIMEOUT_SECONDS)
        raise _too_slow(service) from None


async def _request_with_retries(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    service: str,
    deadline: float,
    kwargs: dict[str, Any],
) -> Any:
    status_retries = 0
    transport_retries = 0
    while True:
        try:
            response = await client.request(method, url, **kwargs)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            failure = (
                f"{service} timed out. Try again later."
                if isinstance(exc, httpx.TimeoutException)
                else f"{service} is unreachable. Try again later."
            )
            if transport_retries >= MAX_TRANSPORT_RETRIES:
                logger.warning("%s %s failed: %s", method, url, failure)
                raise ToolError(failure) from None
            transport_retries += 1
            delay = _backoff(0)
        else:
            status = response.status_code
            if status == 404:
                raise NotFoundError(f"{service} has no record for this request.")
            if status == 429:
                failure = f"{service} is rate limiting requests. Try again later."
            elif status >= 500:
                failure = f"{service} is unavailable (HTTP {status}). Try again later."
            elif status >= 400:
                raise ToolError(f"{service} rejected the request (HTTP {status}).")
            else:
                try:
                    return response.json()
                except ValueError:
                    raise ToolError(f"{service} returned an invalid response.") from None

            if status_retries >= MAX_STATUS_RETRIES:
                logger.warning("%s %s failed after %d retries: %s", method, url, status_retries, failure)
                raise ToolError(failure)
            retry_after = _retry_after_seconds(response)
            delay = retry_after if retry_after is not None else _backoff(status_retries)
            status_retries += 1

        # Sleeping past the deadline cannot succeed; fail now with the real reason.
        if delay >= deadline - asyncio.get_running_loop().time():
            logger.warning("%s %s: retry delay %.2fs exceeds time budget", method, url, delay)
            raise ToolError(failure)
        logger.info("%s %s failed (%s); retrying in %.2fs", method, url, failure, delay)
        await _sleep(delay)
