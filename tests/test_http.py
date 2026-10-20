import asyncio
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from vuln_triage_mcp.clients import _http
from vuln_triage_mcp.clients._http import (
    MAX_STATUS_RETRIES,
    NotFoundError,
    make_http_client,
    request_json,
)

URL = "https://example.test/x"


def test_client_timeouts():
    timeout = make_http_client().timeout
    assert timeout.connect == 3.0
    assert timeout.read == 8.0


@respx.mock
async def test_timeout_then_success(http, sleeps):
    route = respx.get(URL).mock(side_effect=[httpx.ReadTimeout("slow"), httpx.Response(200, json={"ok": True})])

    assert await request_json(http, "GET", URL, service="Svc") == {"ok": True}
    assert route.call_count == 2
    assert len(sleeps) == 1


@respx.mock
async def test_timeout_twice_raises_after_two_calls(http):
    route = respx.get(URL).mock(side_effect=httpx.ConnectTimeout("slow"))

    with pytest.raises(ToolError, match="Svc timed out"):
        await request_json(http, "GET", URL, service="Svc")
    assert route.call_count == 2


@respx.mock
async def test_connection_error_retried_once(http):
    route = respx.get(URL).mock(side_effect=httpx.ConnectError("refused"))

    with pytest.raises(ToolError, match="Svc is unreachable"):
        await request_json(http, "GET", URL, service="Svc")
    assert route.call_count == 2


@respx.mock
async def test_429_then_success_honors_retry_after(http, sleeps):
    route = respx.get(URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "2"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )

    assert await request_json(http, "GET", URL, service="Svc") == {"ok": True}
    assert route.call_count == 2
    assert sleeps == [2.0]


@respx.mock
async def test_retry_after_http_date(http, sleeps):
    when = datetime.now(UTC) + timedelta(seconds=5)
    respx.get(URL).mock(
        side_effect=[
            httpx.Response(503, headers={"Retry-After": format_datetime(when, usegmt=True)}),
            httpx.Response(200, json=[]),
        ]
    )

    await request_json(http, "GET", URL, service="Svc")
    assert len(sleeps) == 1 and 3.0 <= sleeps[0] <= 5.0


@respx.mock
async def test_retry_after_beyond_time_cap_fails_without_sleeping(http, sleeps):
    route = respx.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "120"}))

    with pytest.raises(ToolError, match="Svc is rate limiting"):
        await request_json(http, "GET", URL, service="Svc")
    assert route.call_count == 1
    assert sleeps == []


@respx.mock
async def test_404_single_call(http, sleeps):
    route = respx.get(URL).mock(return_value=httpx.Response(404))

    with pytest.raises(NotFoundError):
        await request_json(http, "GET", URL, service="Svc")
    assert route.call_count == 1
    assert sleeps == []


@respx.mock
@pytest.mark.parametrize("status", [400, 401, 403, 422])
async def test_other_4xx_not_retried(http, sleeps, status):
    route = respx.get(URL).mock(return_value=httpx.Response(status))

    with pytest.raises(ToolError, match=f"HTTP {status}"):
        await request_json(http, "GET", URL, service="Svc")
    assert route.call_count == 1
    assert sleeps == []


@respx.mock
async def test_persistent_503_stops_after_retry_limit(http, sleeps):
    route = respx.get(URL).mock(return_value=httpx.Response(503))

    with pytest.raises(ToolError, match=r"Svc is unavailable \(HTTP 503\)"):
        await request_json(http, "GET", URL, service="Svc")
    assert route.call_count == 1 + MAX_STATUS_RETRIES
    assert len(sleeps) == MAX_STATUS_RETRIES
    assert sleeps == sorted(sleeps)  # exponential backoff grows


@respx.mock
async def test_total_time_cap(http, monkeypatch):
    monkeypatch.setattr(_http, "TOTAL_TIMEOUT_SECONDS", 0.05)

    async def slow_service(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    respx.get(URL).mock(side_effect=slow_service)

    with pytest.raises(ToolError, match="Svc was too slow to respond.*You can retry"):
        await request_json(http, "GET", URL, service="Svc")


@respx.mock
async def test_invalid_json(http):
    respx.get(URL).mock(return_value=httpx.Response(200, text="<html>"))

    with pytest.raises(ToolError, match="invalid response"):
        await request_json(http, "GET", URL, service="Svc")


@respx.mock
async def test_error_message_does_not_leak_body(http):
    respx.get(URL).mock(return_value=httpx.Response(400, text="Traceback (most recent call last): secret"))

    with pytest.raises(ToolError) as exc_info:
        await request_json(http, "GET", URL, service="Svc")
    assert "Traceback" not in str(exc_info.value)
    assert "secret" not in str(exc_info.value)
