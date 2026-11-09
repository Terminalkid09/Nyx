"""Scanner runtime: depth budgets, WAF skip, concurrency, deadlines, wiring."""
import asyncio
import time

import pytest
from httpx import ASGITransport, AsyncClient

from core.config import settings
from core.events.bus import EventBus
from modules.scanner.active.scanner import ActiveScanner
from modules.scanner.base_check import CheckResult, cap_payloads


BASE = {"method": "GET", "url": "https://example.com/?q=1", "headers": {}}


class PayloadCheck:
    def __init__(self):
        self.sent = None

    name = "payload_check"

    async def run(self, base_request, params):
        self.sent = len(cap_payloads(list(range(200))))
        return []


class NamedCheck:
    def __init__(self, name):
        self.name = name
        self.ran = False

    async def run(self, base_request, params):
        self.ran = True
        return []


class FindingCheck:
    name = "finding_check"

    async def run(self, base_request, params):
        return [CheckResult(
            triggered=True, severity="high", title="Hit",
            description="", cwe="CWE-89", param="q",
        )]


class SlowCheck:
    name = "slow_check"

    async def run(self, base_request, params):
        await asyncio.sleep(5)
        return []


@pytest.mark.asyncio
@pytest.mark.parametrize("depth,expected", [("fast", 5), ("balanced", 15), ("deep", 50)])
async def test_depth_caps_payloads(monkeypatch, depth, expected):
    monkeypatch.setattr(settings, "SCAN_MAX_CONCURRENCY", 1)
    check = PayloadCheck()
    scanner = ActiveScanner()
    scanner._checks = [check]
    await scanner.run_checks(BASE, ["q"], event={"session_id": None}, depth=depth)
    assert check.sent == expected


@pytest.mark.asyncio
async def test_budget_is_reset_between_scans():
    check = PayloadCheck()
    scanner = ActiveScanner()
    scanner._checks = [check]
    await scanner.run_checks(BASE, ["q"], event={"session_id": None}, depth="fast")
    assert check.sent == 5
    await scanner.run_checks(BASE, ["q"], event={"session_id": None}, depth="deep")
    assert check.sent == 50
    # Outside a scan the budget must not leak into other callers.
    assert len(cap_payloads(list(range(100)))) == 100


@pytest.mark.asyncio
async def test_fingerprint_waf_skips_checks():
    sqli = NamedCheck("active_sqli")
    other = NamedCheck("active_hsts_missing")
    scanner = ActiveScanner()
    scanner._checks = [sqli, other]

    await scanner.run_checks(
        BASE, ["q"], event={"session_id": None},
        fingerprint_info={"waf": ["cloudflare"], "technologies": []},
    )

    assert sqli.ran is False
    assert other.ran is True


@pytest.mark.asyncio
async def test_malformed_session_id_blocks_the_scan():
    check = FindingCheck()
    scanner = ActiveScanner()
    scanner._checks = [check]

    results = await scanner.run_checks(
        BASE, ["q"], event={"session_id": "not-a-uuid"},
    )

    assert results == []


@pytest.mark.asyncio
async def test_checks_run_concurrently(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_MAX_CONCURRENCY", 2)

    class TimedCheck:
        def __init__(self, name):
            self.name = name

        async def run(self, base_request, params):
            await asyncio.sleep(0.2)
            return []

    scanner = ActiveScanner()
    scanner._checks = [TimedCheck("a"), TimedCheck("b")]
    started = time.monotonic()
    await scanner.run_checks(BASE, ["q"], event={"session_id": None})
    elapsed = time.monotonic() - started

    assert elapsed < 0.35  # sequential would be >= 0.4


@pytest.mark.asyncio
async def test_deadline_returns_finished_checks(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_CHECK_TIMEOUT_SECONDS", 10.0)
    monkeypatch.setattr(settings, "SCAN_MAX_CONCURRENCY", 2)
    scanner = ActiveScanner()
    scanner._checks = [FindingCheck(), SlowCheck()]

    started = time.monotonic()
    results = await scanner.run_checks(
        BASE, ["q"], event={"session_id": None}, deadline_seconds=0.3,
    )
    elapsed = time.monotonic() - started

    assert [r["check"] for r in results] == ["finding_check"]
    assert elapsed < 1.5


@pytest.mark.asyncio
async def test_route_uses_app_scanner_and_session(monkeypatch):
    from main import app

    captured = {}

    class FakeScanner:
        async def run_checks(self, base_request, target_params, event=None,
                             checks_filter=None, depth=None, **kwargs):
            captured.update(event=event, url=base_request.get("url"))
            return []

    previous = getattr(app.state, "active_scanner", None)
    app.state.active_scanner = FakeScanner()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/active-scanner/run", json={
                "base_request": BASE,
                "target_params": ["q"],
                "session_id": "11111111-1111-1111-1111-111111111111",
                "request_id": "22222222-2222-2222-2222-222222222222",
            })
    finally:
        if previous is None:
            delattr(app.state, "active_scanner")
        else:
            app.state.active_scanner = previous

    assert response.status_code == 200
    assert captured["event"]["session_id"] == "11111111-1111-1111-1111-111111111111"
    assert captured["event"]["request_id"] == "22222222-2222-2222-2222-222222222222"
    assert captured["event"]["url"] == BASE["url"]


def test_base_request_is_translated_for_httpx():
    from modules.scanner.active.scanner import normalize_base_request

    normalised = normalize_base_request({
        "method": "POST", "url": "https://example.com/",
        "headers": {}, "body": "a=1",
    })
    assert normalised["content"] == "a=1"
    assert "body" not in normalised

    # An explicit content/data wins and the duplicate body key is dropped.
    both = normalize_base_request({"body": "x", "content": "y", "url": "https://x/"})
    assert both["content"] == "y" and "body" not in both


def test_pipeline_scanner_has_event_bus():
    from modules.pipeline.orchestrator import ScanPipeline

    bus = EventBus()
    scanner = ScanPipeline(bus)._active_scanner()
    assert scanner.event_bus is bus
