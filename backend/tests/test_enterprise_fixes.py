"""Regression tests for the enterprise hardening fixes.

Covers: WebSocket origin validation, portable scan-job queue ordering,
plugin path validation on update, live-audit finding counting, fuzzer
wordlist path confinement, and the non-leaking exception handler.
"""
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.events.bus import EventBus
from core.storage.models import Base, ScanJob


# ── WS origin validation ─────────────────────────────────────────────────────

class TestWsOriginValidation:
    def _ws(self, origin=None):
        headers = {}
        if origin is not None:
            headers["origin"] = origin
        return SimpleNamespace(headers=headers)

    def test_allows_no_origin(self):
        from core.api_auth import validate_ws_origin
        assert validate_ws_origin(self._ws()) is True

    def test_allows_same_origin_api(self):
        from core.api_auth import validate_ws_origin
        assert validate_ws_origin(self._ws("http://127.0.0.1:8000")) is True
        assert validate_ws_origin(self._ws("http://localhost:8000")) is True

    def test_allows_vite_dev_server(self):
        from core.api_auth import validate_ws_origin
        assert validate_ws_origin(self._ws("http://localhost:5173")) is True

    def test_rejects_foreign_origin(self):
        from core.api_auth import validate_ws_origin
        assert validate_ws_origin(self._ws("http://evil.example.com")) is False

    def test_rejects_foreign_port_on_localhost(self):
        from core.api_auth import validate_ws_origin
        assert validate_ws_origin(self._ws("http://127.0.0.1:9999")) is False

    def test_rejects_non_http_scheme(self):
        from core.api_auth import validate_ws_origin
        assert validate_ws_origin(self._ws("file:///etc/passwd")) is False


# ── Scan job queue ordering (SQLite-portable) ────────────────────────────────

@pytest_asyncio.fixture
async def queue_client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    now = datetime.now(timezone.utc)
    async with session_maker() as db:
        # Inserted deliberately out of priority order.
        db.add_all([
            ScanJob(session_id=uuid.uuid4(), scan_type="active", target_url="https://x/low",
                    config={"priority": 1}, status="pending",
                    created_at=now - timedelta(seconds=3)),
            ScanJob(session_id=uuid.uuid4(), scan_type="active", target_url="https://x/high",
                    config={"priority": 9}, status="pending",
                    created_at=now - timedelta(seconds=2)),
            ScanJob(session_id=uuid.uuid4(), scan_type="active", target_url="https://x/mid-old",
                    config={"priority": 5}, status="pending",
                    created_at=now - timedelta(seconds=4)),
            ScanJob(session_id=uuid.uuid4(), scan_type="active", target_url="https://x/mid-new",
                    config={"priority": 5}, status="pending",
                    created_at=now),
            ScanJob(session_id=uuid.uuid4(), scan_type="active", target_url="https://x/done",
                    config={"priority": 100}, status="completed",
                    created_at=now),
        ])
        await db.commit()

    from api.deps import get_db
    from api.routes.scan_jobs import router

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
async def test_scan_queue_orders_by_priority_then_age(queue_client):
    resp = await queue_client.get("/api/scan-jobs/queue")
    assert resp.status_code == 200
    urls = [job["target_url"] for job in resp.json()]
    # Priority DESC, then created_at ASC within the same priority; completed excluded.
    assert urls == [
        "https://x/high",
        "https://x/mid-old",
        "https://x/mid-new",
        "https://x/low",
    ]


# ── Plugin path validation on update ─────────────────────────────────────────

class TestPluginPathValidation:
    def test_rejects_path_outside_plugins_dir(self):
        from api.routes.plugins import _validate_plugin_path
        with pytest.raises(HTTPException) as exc:
            _validate_plugin_path("C:/Windows/system32/evil.py")
        assert exc.value.status_code == 400

    def test_rejects_traversal(self):
        from api.routes.plugins import _validate_plugin_path
        with pytest.raises(HTTPException):
            _validate_plugin_path("../../evil.py")

    def test_rejects_missing_file_inside_plugins_dir(self):
        from api.routes.plugins import _validate_plugin_path
        with pytest.raises(HTTPException) as exc:
            _validate_plugin_path("definitely_not_here.py")
        assert exc.value.status_code == 400


# ── Live audit finding counting ───────────────────────────────────────────────

class TestLiveAuditCounting:
    @pytest.mark.asyncio
    async def test_counts_findings_by_source(self):
        import asyncio
        from modules.live_audit.service import LiveAuditService

        bus = EventBus()
        service = LiveAuditService(bus)
        await service.start()

        await bus.publish({"type": "finding.created", "id": str(uuid.uuid4()),
                           "source": "passive", "module": "XssCheck", "severity": "high",
                           "title": "t1"})
        await bus.publish({"type": "finding.created", "id": str(uuid.uuid4()),
                           "source": "passive", "module": "SqliCheck", "severity": "high",
                           "title": "t2"})
        await bus.publish({"type": "finding.created", "id": str(uuid.uuid4()),
                           "source": "active", "module": "NoSqlInjectionActiveCheck",
                           "severity": "high", "title": "t3"})
        await asyncio.sleep(0)

        stats = service.get_status()["stats"]
        assert stats["passive_findings"] == 2
        assert stats["active_findings"] == 1

        await service.stop()
        # After stop, findings are no longer counted.
        await bus.publish({"type": "finding.created", "id": str(uuid.uuid4()),
                           "source": "passive", "module": "X", "severity": "low",
                           "title": "t4"})
        await asyncio.sleep(0)
        assert service.get_status()["stats"]["passive_findings"] == 2


# ── Fuzzer wordlist path confinement ─────────────────────────────────────────

class TestFuzzerWordlistConfinement:
    def _service(self, tmp_path):
        from modules.fuzzer.service import FuzzerService
        return FuzzerService(event_bus=EventBus(), wordlists_dir=tmp_path)

    def test_rejects_absolute_path_outside_allowed_roots(self, tmp_path):
        service = self._service(tmp_path)
        assert service.expand_wordlist("C:/Windows/win.ini") == []
        assert service.expand_wordlist("/etc/passwd") == []

    def test_accepts_wordlist_inside_configured_dir(self, tmp_path):
        wl = tmp_path / "params.txt"
        wl.write_text("q\nid\npage\n")
        service = self._service(tmp_path)
        assert service.expand_wordlist(str(wl)) == ["q", "id", "page"]

    def test_relative_path_still_resolves(self, tmp_path):
        (tmp_path / "relative.txt").write_text("a\nb\n")
        service = self._service(tmp_path)
        assert service.expand_wordlist("relative.txt") == ["a", "b"]


# ── Exception handler does not leak internals ────────────────────────────────

class TestExceptionHandlerNoLeak:
    @pytest.mark.asyncio
    async def test_generic_detail_with_request_id(self):
        from main import global_exception_handler

        request = SimpleNamespace(
            method="GET",
            url=SimpleNamespace(path="/api/secret"),
        )
        exc = RuntimeError("password=hunter2 at C:/Users/me/db.sqlite")
        response = await global_exception_handler(request, exc)

        import json
        body = json.loads(response.body.decode())
        assert response.status_code == 500
        assert body["detail"] == "Internal server error"
        assert "hunter2" not in response.body.decode()
        assert "C:/Users" not in response.body.decode()
        assert len(body["request_id"]) == 8
