import pytest

from vuln_triage_mcp.clients import _http


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    """Record retry delays instead of sleeping."""
    recorded: list[float] = []

    async def fake_sleep(delay: float) -> None:
        recorded.append(delay)

    monkeypatch.setattr(_http, "_sleep", fake_sleep)
    return recorded


@pytest.fixture
async def http():
    async with _http.make_http_client() as client:
        yield client
