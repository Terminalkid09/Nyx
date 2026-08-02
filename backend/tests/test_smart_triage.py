import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.storage.models import (
    Base,
    Session as SessionModel,
    Request as RequestModel,
    Finding,
    SeverityEnum,
)


def _now():
    return datetime.now(timezone.utc)


@pytest_asyncio.fixture
async def triage_api():
    """In-memory DB seeded with two sessions, plus a FastAPI app whose triage
    queries are scoped via the session_id query param (as in production)."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sid_a, sid_b = uuid.uuid4(), uuid.uuid4()

    async with session_maker() as db:
        db.add_all([
            SessionModel(id=sid_a, name="Session A"),
            SessionModel(id=sid_b, name="Session B"),
        ])
        await db.flush()

        req_a = RequestModel(id=uuid.uuid4(), session_id=sid_a, method="GET",
                             url="https://a.example.com/login", host="a.example.com",
                             path="/login", request_headers={"Host": "a.example.com"},
                             timestamp=_now())
        req_b = RequestModel(id=uuid.uuid4(), session_id=sid_b, method="POST",
                             url="https://b.example.com/admin", host="b.example.com",
                             path="/admin", request_headers={"Host": "b.example.com"},
                             timestamp=_now())
        db.add_all([req_a, req_b])
        await db.flush()

        db.add_all([
            Finding(session_id=sid_a, request_id=req_a.id, module="scanner",
                    severity=SeverityEnum.HIGH, title="SQLi in A",
                    description="found on session A", evidence="evA"),
            Finding(session_id=sid_a, request_id=req_a.id, module="scanner",
                    severity=SeverityEnum.LOW, title="Info leak in A",
                    description="found on session A", evidence="evA2"),
            Finding(session_id=sid_b, request_id=req_b.id, module="scanner",
                    severity=SeverityEnum.CRITICAL, title="RCE in B",
                    description="found on session B", evidence="evB"),
        ])
        await db.commit()

    from api.deps import get_db
    from api.routes.smart_triage import router

    async def _get_db():
        async with session_maker() as db:
            yield db

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = _get_db

    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    try:
        yield client, sid_a, sid_b
    finally:
        await client.aclose()
        await engine.dispose()


class TestTriageSessionIsolation:
    @pytest.mark.asyncio
    async def test_grouped_scoped_to_session(self, triage_api):
        client, sid_a, sid_b = triage_api

        resp = await client.get("/api/triage/findings/grouped", params={"session_id": str(sid_a)})
        assert resp.status_code == 200
        groups = resp.json()["groups"]
        # Session A has two findings with different titles on the same endpoint.
        assert len(groups) == 2
        assert all(g["request_session_id"] == str(sid_a) for g in groups)
        assert {g["title"] for g in groups} == {"SQLi in A", "Info leak in A"}
        assert all(g["host"] == "a.example.com" for g in groups)

        resp_b = await client.get("/api/triage/findings/grouped", params={"session_id": str(sid_b)})
        groups_b = resp_b.json()["groups"]
        assert len(groups_b) == 1
        assert groups_b[0]["title"] == "RCE in B"
        assert groups_b[0]["count"] == 1
        # Session A's findings must NOT leak into session B.
        assert "SQLi in A" not in {g["title"] for g in groups_b}

    @pytest.mark.asyncio
    async def test_stats_scoped_to_session(self, triage_api):
        client, sid_a, sid_b = triage_api

        resp = await client.get("/api/triage/stats", params={"session_id": str(sid_a)})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_findings"] == 2
        assert body["high"] == 1
        assert body["low"] == 1
        assert body["critical"] == 0

        resp_b = await client.get("/api/triage/stats", params={"session_id": str(sid_b)})
        body_b = resp_b.json()
        assert body_b["total_findings"] == 1
        assert body_b["critical"] == 1
        assert body_b["high"] == 0

    @pytest.mark.asyncio
    async def test_recent_scoped_to_session(self, triage_api):
        client, sid_a, sid_b = triage_api

        resp = await client.get("/api/triage/findings/recent",
                                params={"session_id": str(sid_a), "hours": 24})
        body = resp.json()
        assert len(body) == 2
        assert all("A" in f["title"] for f in body)
        assert all(f["url"].startswith("https://a.example.com") for f in body)

    @pytest.mark.asyncio
    async def test_missing_session_id_rejected(self, triage_api):
        client, _, _ = triage_api
        resp = await client.get("/api/triage/findings/grouped")
        assert resp.status_code == 422