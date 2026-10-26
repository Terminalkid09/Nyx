"""Session lifecycle: create, switch, reset data, delete.

The UI attributes captured traffic and findings to the *active* session, and
several screens used to hard-code the default session id instead. These tests
pin the backend contract those screens rely on.
"""
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from core.storage.database import AsyncSessionLocal
from core.storage.models import Finding, SeverityEnum
from main import app


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _create(client: AsyncClient, name: str = "sess") -> dict:
    response = await client.post("/api/sessions", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_session_round_trip(client):
    async with client as c:
        created = await _create(c, "round-trip")
        assert uuid.UUID(created["id"])

        listed = await c.get("/api/sessions")
        assert listed.status_code == 200
        assert any(s["id"] == created["id"] for s in listed.json())

        fetched = await c.get(f"/api/sessions/{created['id']}")
        assert fetched.status_code == 200
        assert fetched.json()["name"] == "round-trip"

        renamed = await c.put(f"/api/sessions/{created['id']}", json={"name": "renamed"})
        assert renamed.status_code == 200
        assert renamed.json()["name"] == "renamed"

        deleted = await c.delete(f"/api/sessions/{created['id']}")
        assert deleted.status_code == 204

        gone = await c.get(f"/api/sessions/{created['id']}")
        assert gone.status_code == 404


@pytest.mark.asyncio
async def test_delete_session_with_captured_traffic(client):
    """Deleting a session that holds requests must not 500.

    The ORM cascade tried to NULL ``requests.session_id`` (NOT NULL), so
    deleting a session that had captured traffic raised IntegrityError.
    """
    from core.storage.models import Request

    async with client as c:
        created = await _create(c, "with-traffic")
        session_id = uuid.UUID(created["id"])

        async with AsyncSessionLocal() as db:
            db.add(Request(
                session_id=session_id, method="GET", url="http://example.com/",
                host="example.com", path="/",
            ))
            db.add(Finding(
                session_id=session_id, severity=SeverityEnum.HIGH, module="test",
                title="planted", description="",
            ))
            await db.commit()

        deleted = await c.delete(f"/api/sessions/{created['id']}")
        assert deleted.status_code == 204, deleted.text

        from sqlalchemy import func, select

        async with AsyncSessionLocal() as db:
            requests_left = (await db.execute(
                select(func.count(Request.id)).where(Request.session_id == session_id)
            )).scalar()
            findings_left = (await db.execute(
                select(func.count(Finding.id)).where(Finding.session_id == session_id)
            )).scalar()
        assert requests_left == 0
        assert findings_left == 0


@pytest.mark.asyncio
async def test_proxy_session_switch_rejects_bad_uuid(client):
    async with client as c:
        bad = await c.patch("/api/proxy/session", json={"session_id": "not-a-uuid"})
        assert bad.status_code in (400, 503)


@pytest.mark.asyncio
async def test_reset_session_data_keeps_session(client):
    async with client as c:
        created = await _create(c, "reset-me")
        session_id = uuid.UUID(created["id"])

        async with AsyncSessionLocal() as db:
            db.add(Finding(
                session_id=session_id,
                severity=SeverityEnum.HIGH,
                module="test",
                title="planted finding",
                description="",
            ))
            await db.commit()

        reset = await c.delete(f"/api/sessions/{created['id']}/data")
        assert reset.status_code == 204

        from sqlalchemy import func, select

        async with AsyncSessionLocal() as db:
            count = (await db.execute(
                select(func.count(Finding.id)).where(Finding.session_id == session_id)
            )).scalar()
        assert count == 0

        still_there = await c.get(f"/api/sessions/{created['id']}")
        assert still_there.status_code == 200


@pytest.mark.asyncio
async def test_unknown_session_returns_404(client):
    async with client as c:
        missing = uuid.uuid4()
        assert (await c.get(f"/api/sessions/{missing}")).status_code == 404
        assert (await c.delete(f"/api/sessions/{missing}")).status_code == 404
        assert (await c.delete(f"/api/sessions/{missing}/data")).status_code == 404
