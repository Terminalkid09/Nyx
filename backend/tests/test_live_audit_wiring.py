"""BUG-03/BUG-16: Live Audit toggles must drive the engine, and queued scans
must keep the originating session so findings are not written to the default
session.
"""
import asyncio

import pytest

from core.events.bus import EventBus
from modules.automation.engine import AutoScanEngine
from modules.live_audit.service import LiveAuditService

SESSION = "11111111-1111-1111-1111-111111111111"


class FakeScanner:
    def __init__(self):
        self.calls = []

    async def run_checks(self, base_request, params, event=None, depth=None):
        self.calls.append({"event": event, "params": params, "depth": depth})
        return [{"check": "active_sqli"}]

    async def discover_params(self, url, concurrency=5):
        return [{"name": "hidden"}]


@pytest.mark.asyncio
async def test_scan_url_propagates_session_and_emits_completion():
    bus = EventBus()
    completed = []

    async def collect(event):
        completed.append(event)

    bus.subscribe("automation.scan_completed", collect)
    scanner = FakeScanner()
    engine = AutoScanEngine(bus, None, scanner)
    engine.enforce_scope = False

    await engine._scan_url({
        "url": "https://example.com/a?x=1",
        "params": ["x"],
        "session_id": SESSION,
        "request_id": None,
    })
    await asyncio.sleep(0.05)

    assert scanner.calls[0]["event"]["session_id"] == SESSION
    assert scanner.calls[0]["depth"] == "fast"
    assert completed and completed[0]["findings"] == 1


@pytest.mark.asyncio
async def test_active_scan_toggle_drives_engine_and_restores_on_stop():
    bus = EventBus()
    engine = AutoScanEngine(bus, None, FakeScanner())
    engine.auto_active_scan = False
    engine.enforce_scope = True
    service = LiveAuditService(bus, engine)

    await service.start()
    assert engine.auto_active_scan is True
    assert service.get_config()["active_scan"] is True

    service.update_config({"active_scan": False, "scope_only": False})
    assert engine.auto_active_scan is False
    assert engine.enforce_scope is False

    await service.stop()
    assert engine.auto_active_scan is False
    assert engine.enforce_scope is True


@pytest.mark.asyncio
async def test_scan_counters_follow_engine_events():
    bus = EventBus()
    service = LiveAuditService(bus, None)
    await service.start()

    await bus.publish({"type": "automation.scan_started", "url": "https://e.com"})
    await bus.publish({"type": "automation.scan_completed", "url": "https://e.com"})
    await asyncio.sleep(0.05)

    stats = service.get_status()["stats"]
    assert stats["active_scans_queued"] == 1
    assert stats["active_scans_completed"] == 1
    await service.stop()


@pytest.mark.asyncio
async def test_param_discovery_queues_only_when_active_scan_enabled():
    bus = EventBus()
    scanner = FakeScanner()
    engine = AutoScanEngine(bus, None, scanner)
    engine.auto_param_discovery = True
    engine.auto_active_scan = True

    await engine._on_request_captured({
        "url": "https://example.com/no-params",
        "session_id": SESSION,
    })
    await asyncio.sleep(0.1)

    assert engine.pending_queue
    assert engine.pending_queue[0]["params"] == ["hidden"]
    assert engine.pending_queue[0]["session_id"] == SESSION
