"""Tests for traffic features: QUIC/HTTP3 blocking and HAR export."""
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.storage.models import Base, Request as RequestModel


# ── QUIC / HTTP3 blocking ────────────────────────────────────────────────────

class TestQuicBlock:
    def _pkt(self, protocol=17, dst_port=443, src_addr="192.168.1.163"):
        return SimpleNamespace(protocol=protocol, dst_port=dst_port, src_addr=src_addr)

    def setup_method(self):
        from core.proxy import engine
        engine.quic_block_clear()

    def teardown_method(self):
        from core.proxy import engine
        engine.quic_block_clear()

    def test_drops_target_quic(self):
        from core.proxy import engine
        engine.quic_block_set_targets({"192.168.1.163"})
        assert engine._should_drop_quic(self._pkt()) is True

    def test_keeps_non_target_quic(self):
        from core.proxy import engine
        engine.quic_block_set_targets({"192.168.1.163"})
        assert engine._should_drop_quic(self._pkt(src_addr="192.168.1.99")) is False

    def test_keeps_target_tcp_443(self):
        from core.proxy import engine
        engine.quic_block_set_targets({"192.168.1.163"})
        assert engine._should_drop_quic(self._pkt(protocol=6)) is False

    def test_keeps_target_udp_other_port(self):
        from core.proxy import engine
        engine.quic_block_set_targets({"192.168.1.163"})
        assert engine._should_drop_quic(self._pkt(dst_port=53)) is False

    def test_disabled_when_no_targets(self):
        from core.proxy import engine
        assert engine._should_drop_quic(self._pkt()) is False

    def test_set_targets_resets_counter(self):
        from core.proxy import engine
        engine.quic_block_set_targets({"10.0.0.1"})
        engine._QUIC_DROPPED_COUNT = 123
        engine.quic_block_set_targets({"10.0.0.2"})
        assert engine.quic_dropped_count() == 0


# ── HAR export ────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def har_client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    sid = uuid.uuid4()
    now = datetime.now(timezone.utc)
    async with session_maker() as db:
        db.add_all([
            RequestModel(
                session_id=sid, method="GET", url="https://api.example.com/v1/users",
                host="api.example.com", path="/v1/users",
                request_headers={"Host": "api.example.com", "Accept": "application/json"},
                request_body=None,
                response_status=200, response_reason="OK",
                response_headers={"Content-Type": "application/json"},
                response_body='{"users": []}', response_content_type="application/json",
                response_size_bytes=12, response_time_ms=42,
                timestamp=now,
            ),
            RequestModel(
                session_id=sid, method="POST", url="https://api.example.com/v1/login",
                host="api.example.com", path="/v1/login",
                request_headers={"Content-Type": "application/json"},
                request_body='{"u":"a","p":"b"}',
                response_status=401, response_reason="Unauthorized",
                response_headers={}, response_body="denied",
                response_content_type="text/plain", timestamp=now,
            ),
        ])
        await db.commit()

    from api.deps import get_db
    from api.routes.requests import router

    async def _get_db():
        async with session_maker() as db:
            yield db

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = _get_db
    client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    try:
        yield client
    finally:
        await client.aclose()
        await engine.dispose()


@pytest.mark.asyncio
async def test_har_export_structure(har_client):
    resp = await har_client.get("/api/requests/export/har")
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")
    log = resp.json()["log"]
    assert log["version"] == "1.2"
    assert len(log["entries"]) == 2

    by_url = {e["request"]["url"]: e for e in log["entries"]}
    e0 = by_url["https://api.example.com/v1/users"]
    assert e0["request"]["method"] == "GET"
    assert e0["response"]["status"] == 200
    assert e0["response"]["content"]["mimeType"] == "application/json"
    assert e0["startedDateTime"].endswith("Z")

    e1 = by_url["https://api.example.com/v1/login"]
    assert e1["request"]["method"] == "POST"
    assert e1["request"]["postData"]["text"] == '{"u":"a","p":"b"}'
    assert e1["response"]["status"] == 401