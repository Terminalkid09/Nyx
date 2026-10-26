"""Every active component passes the authorization gate, not only the scanner."""
import pytest

from core.events.bus import EventBus
from modules.automations.param_chain import ParamDiscoveryService
from modules.crawler.service import CrawlerService


@pytest.mark.asyncio
async def test_authorize_accepts_string_session_ids():
    # Routes pass the session id as a JSON string; the scope query binds a
    # UUID column and used to raise before returning a decision.
    from core.authorization import authorize

    allowed, kind, detail = await authorize(
        "11111111-1111-1111-1111-111111111111", "https://example.com/"
    )
    assert allowed is True and kind is None and detail is None


@pytest.mark.asyncio
async def test_authorize_rejects_malformed_session_ids():
    from core.authorization import authorize

    allowed, kind, detail = await authorize("not-a-uuid", "https://example.com/")
    assert allowed is False
    assert kind == "invalid_session"
    assert detail == "not-a-uuid"


@pytest.mark.asyncio
async def test_crawler_refuses_out_of_scope(monkeypatch):
    async def _deny(session_id, url):
        return False, "out_of_scope", "deny-example"

    monkeypatch.setattr("modules.crawler.service.authorize", _deny)
    bus = EventBus()
    blocked = []

    async def collect(event):
        blocked.append(event)

    bus.subscribe("crawl.blocked", collect)

    result = await CrawlerService(bus).crawl(
        "https://example.com/", job_id="gate-test", session_id=None,
    )

    import asyncio
    await asyncio.sleep(0.05)

    assert result["status"] == "blocked"
    assert result["discovered_urls"] == []
    assert blocked and blocked[0]["rule"] == "deny-example"


@pytest.mark.asyncio
async def test_crawler_rechecks_each_discovered_url(monkeypatch):
    requested = []

    class FakeResponse:
        text = '<a href="https://example.com/blocked">blocked</a>'

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, follow_redirects=True):
            requested.append(url)
            return FakeResponse()

    async def conditional(session_id, url):
        if url.endswith("/blocked"):
            return False, "roe", "excluded"
        return True, None, None

    async def no_pace(url):
        return None

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: FakeClient())
    monkeypatch.setattr("modules.crawler.service.authorize", conditional)
    monkeypatch.setattr("modules.crawler.service.pace", no_pace)

    service = CrawlerService(EventBus())
    await service._fallback_bfs(
        "https://example.com/", "example.com", 1, 10, [], [], []
    )

    assert requested == ["https://example.com/"]


@pytest.mark.asyncio
async def test_param_discovery_refuses_out_of_scope(monkeypatch):
    async def _deny(session_id, url):
        return False, "roe", "not_targeted"

    monkeypatch.setattr("modules.automations.param_chain.authorize", _deny)
    bus = EventBus()
    blocked = []

    async def collect(event):
        blocked.append(event)

    bus.subscribe("param_discovery.blocked", collect)

    result = await ParamDiscoveryService(bus).discover("https://example.com/")

    import asyncio
    await asyncio.sleep(0.05)

    assert result["blocked"] is True
    assert result["discovered_params"] == []
    assert blocked and blocked[0]["rule"] == "not_targeted"


@pytest.mark.asyncio
async def test_scope_rule_create_serializes_created_at():
    from httpx import ASGITransport, AsyncClient

    from main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/scope/", json={
            "name": "sweep", "rule_type": "include", "pattern": "example.com",
        })
        assert created.status_code == 201, created.text
        payload = created.json()
        assert isinstance(payload["created_at"], str)

        listed = await client.get("/api/scope/")
        assert listed.status_code == 200

        await client.delete(f"/api/scope/{payload['id']}")
