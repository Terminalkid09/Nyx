"""Every active component passes the authorization gate, not only the scanner."""
import uuid

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


# Every HTTP entry point that launches its own outbound probe must carry the
# engagement's session. The live review bypassed the session scope rules by
# simply omitting session_id from the body: the service then evaluated
# authorize(None, url), which skipped the scope query entirely.
ACTIVE_ROUTES = [
    ("/api/active-scanner/run", {
        "base_request": {"method": "GET", "url": "http://127.0.0.1/", "headers": {}},
        "target_params": ["q"],
    }),
    ("/api/auto-exploit/verify", {"url": "http://127.0.0.1/"}),
    ("/api/auto-exploit/execute", {
        "finding": {"cwe": "CWE-89", "title": "SQLi"},
        "url": "http://127.0.0.1/?id=1",
        "param": "id",
    }),
    ("/api/ab-test/run", {
        "url": "http://127.0.0.1/",
        "identity_a": {"name": "a"},
        "identity_b": {"name": "b"},
    }),
    ("/api/crawler/start", {"start_url": "http://127.0.0.1/"}),
    ("/api/content-discovery/start", {
        "target_url": "http://127.0.0.1/",
        "wordlist_path": "missing.txt",
    }),
    ("/api/repeater/send", {"method": "GET", "url": "http://127.0.0.1/"}),
    ("/api/pipeline/start", {"target_url": "http://127.0.0.1/"}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", ACTIVE_ROUTES)
async def test_active_routes_reject_a_missing_session(path, body):
    from httpx import ASGITransport, AsyncClient

    from main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(path, json=body)
    assert response.status_code == 422, f"{path}: {response.status_code} {response.text}"


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", ACTIVE_ROUTES)
async def test_active_routes_reject_an_out_of_scope_session(path, body):
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import delete

    from core.storage.database import AsyncSessionLocal
    from core.storage.models import Session, TargetScopeRule
    from main import app

    session_id = uuid.uuid4()
    async with AsyncSessionLocal() as db:
        db.add(Session(id=session_id, name=f"gate-{session_id}"))
        db.add(TargetScopeRule(
            session_id=session_id, name="only-allowed",
            rule_type="include", pattern="allowed.example",
        ))
        await db.commit()

    try:
        payload = {**body, "session_id": str(session_id)}
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(path, json=payload)
        assert response.status_code == 403, f"{path}: {response.status_code} {response.text}"
        assert "not authorized" in response.json()["detail"].lower()
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(TargetScopeRule).where(TargetScopeRule.session_id == session_id))
            await db.execute(delete(Session).where(Session.id == session_id))
            await db.commit()


@pytest.mark.asyncio
async def test_scope_check_uses_only_the_requested_engagement():
    from httpx import ASGITransport, AsyncClient
    from sqlalchemy import delete

    from core.storage.database import AsyncSessionLocal
    from core.storage.models import Session, TargetScopeRule
    from main import app

    session_a = uuid.uuid4()
    session_b = uuid.uuid4()
    async with AsyncSessionLocal() as db:
        db.add(Session(id=session_a, name=f"scope-a-{session_a}"))
        db.add(Session(id=session_b, name=f"scope-b-{session_b}"))
        db.add(TargetScopeRule(
            session_id=session_b, name="sweep-b",
            rule_type="include", pattern="192.0.2.10",
        ))
        await db.commit()

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            other = await client.post("/api/scope/check", json={
                "url": "http://127.0.0.1/",
                "session_id": str(session_a),
            })
            own = await client.post("/api/scope/check", json={
                "url": "http://127.0.0.1/",
                "session_id": str(session_b),
            })
        assert other.status_code == 200, other.text
        assert other.json()["in_scope"] is True  # A has no rules of its own
        assert own.status_code == 200, own.text
        assert own.json()["in_scope"] is False
        assert own.json()["matched_by"] is None
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(TargetScopeRule).where(TargetScopeRule.session_id.in_([session_a, session_b])))
            await db.execute(delete(Session).where(Session.id.in_([session_a, session_b])))
            await db.commit()
