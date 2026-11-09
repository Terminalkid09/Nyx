"""BUG-09: paused flows must not hang the target forever."""
from types import SimpleNamespace

import pytest

from core.config import settings
from core.events.bus import EventBus
from modules.interceptor.engine import InterceptorEngine


class FakeFlow:
    def __init__(self):
        self.response = None
        self.resumed = False

    def resume(self):
        self.resumed = True


@pytest.mark.asyncio
async def test_expired_flow_resumes_with_504(monkeypatch):
    import asyncio

    monkeypatch.setattr(settings, "INTERCEPTOR_PAUSE_TTL_SECONDS", 0.01)
    bus = EventBus()
    engine = InterceptorEngine(bus, proxy_engine=None)
    # The mitmproxy loop is captured on the first hook call in production.
    engine._mitmproxy_loop = asyncio.get_running_loop()
    flow = FakeFlow()
    item_id = "11111111-1111-1111-1111-111111111111"

    with engine._lock:
        engine._paused_flows[item_id] = flow
        engine.paused_items[item_id] = {"id": item_id, "status": "paused"}

    await engine._expire_item(item_id)
    await asyncio.sleep(0)

    assert flow.resumed is True
    assert flow.response is not None
    assert flow.response.status_code == 504
    assert item_id not in engine._paused_flows
    assert item_id not in engine.paused_items


@pytest.mark.asyncio
async def test_already_handled_item_is_a_noop(monkeypatch):
    monkeypatch.setattr(settings, "INTERCEPTOR_PAUSE_TTL_SECONDS", 0.01)
    bus = EventBus()
    engine = InterceptorEngine(bus, proxy_engine=None)
    # Nothing paused: expiry must not raise or publish a bogus resume.
    await engine._expire_item("22222222-2222-2222-2222-222222222222")
    assert engine._paused_flows == {}
