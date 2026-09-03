"""Tests for the guaranteed network-state cleanup: /api/shutdown endpoint,
idempotent full cleanup, and the emergency (signal/atexit) path."""
import asyncio
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient

import main as nyx_main


@pytest.fixture(autouse=True)
def _reset_shutdown_flags():
    nyx_main._shutdown_started.clear()
    yield
    # LEAVE the flag set after each test: pytest's interpreter exit fires
    # atexit -> _emergency_cleanup; with the flag clear that would run the
    # REAL proxy_engine.stop() (subprocesses, driver state) from the test run.
    nyx_main._shutdown_started.set()


class TestShutdownEndpoint:
    @pytest.mark.asyncio
    async def test_localhost_request_triggers_delayed_exit(self, monkeypatch):
        called = {"exit": False}
        monkeypatch.setattr(nyx_main, "_begin_delayed_exit", lambda delay=0.5: called.__setitem__("exit", True))
        async with AsyncClient(transport=ASGITransport(app=nyx_main.app), base_url="http://test") as client:
            resp = await client.post("/api/shutdown")
        assert resp.status_code == 200
        assert resp.json()["status"] == "shutting_down"
        assert called["exit"] is True

    @pytest.mark.asyncio
    async def test_full_cleanup_is_idempotent(self, monkeypatch):
        calls = {"shutdown_mitm": 0, "engine_stop": 0}

        class _FakeMitm:
            @staticmethod
            async def shutdown_mitm():
                calls["shutdown_mitm"] += 1

        import sys
        monkeypatch.setitem(sys.modules, "api.routes.mitm", _FakeMitm)

        class _FakeEngine:
            @staticmethod
            def stop():
                calls["engine_stop"] += 1

        monkeypatch.setattr(nyx_main, "proxy_engine", _FakeEngine())

        await nyx_main._full_shutdown_cleanup()
        await nyx_main._full_shutdown_cleanup()  # second call must be a no-op
        assert calls["shutdown_mitm"] == 1
        assert calls["engine_stop"] == 1


class TestEmergencyCleanup:
    def test_emergency_cleanup_stops_engine_once(self, monkeypatch):
        calls = {"stop": 0}

        class _FakeEngine:
            @staticmethod
            def stop():
                calls["stop"] += 1

        monkeypatch.setattr(nyx_main, "proxy_engine", _FakeEngine())
        nyx_main._emergency_cleanup()
        nyx_main._emergency_cleanup()  # guarded by the flag
        assert calls["stop"] == 1

    def test_emergency_cleanup_survives_engine_errors(self, monkeypatch):
        class _BrokenEngine:
            @staticmethod
            def stop():
                raise RuntimeError("boom")

        monkeypatch.setattr(nyx_main, "proxy_engine", _BrokenEngine())
        # Must not raise; flag is still set so atexit won't retry.
        nyx_main._emergency_cleanup()
        assert nyx_main._shutdown_started.is_set()

    def test_signal_handlers_registered(self):
        # SIGINT/SIGTERM/SIGBREAK wiring is recorded at import; pytest owns
        # the live SIGINT handler, so we check our registration log instead.
        assert len(nyx_main._SIGNAL_HANDLERS_REGISTERED) >= 1
        assert callable(nyx_main._signal_handler)
