"""BUG-06/BUG-07: scope is a barrier and a hung check cannot stall the scan."""
import asyncio

import pytest

from core.config import settings
from core.events.bus import EventBus
from modules.scanner.active.scanner import ActiveScanner
from modules.scanner.base_check import CheckResult


class SlowCheck:
    name = "slow_check"

    async def run(self, base_request, params):
        await asyncio.sleep(5)
        return []


class FindingCheck:
    name = "finding_check"

    async def run(self, base_request, params):
        return [CheckResult(
            triggered=True, severity="high", title="SQLi",
            description="", cwe="CWE-89", param=params[0],
        )]


@pytest.mark.asyncio
async def test_hung_check_times_out_and_scan_continues(monkeypatch):
    monkeypatch.setattr(settings, "SCAN_CHECK_TIMEOUT_SECONDS", 0.01)
    bus = EventBus()
    timeouts = []

    async def collect(event):
        timeouts.append(event)

    bus.subscribe("scan.check_timeout", collect)

    scanner = ActiveScanner(bus)
    scanner._checks = [SlowCheck(), FindingCheck()]

    results = await scanner.run_checks(
        {"method": "GET", "url": "https://example.com/?x=1", "headers": {}},
        ["x"],
        event={"session_id": None},
    )
    await asyncio.sleep(0.05)

    assert [r["check"] for r in results] == ["finding_check"]
    assert timeouts and timeouts[0]["check"] == "slow_check"


@pytest.mark.asyncio
async def test_out_of_scope_target_is_never_probed(monkeypatch):
    bus = EventBus()
    skipped = []

    async def collect(event):
        skipped.append(event)

    bus.subscribe("scan.skipped", collect)

    async def deny(session_id, url):
        return False, "out_of_scope", "deny-example"

    # run_checks imports the choke point lazily, so patch it there.
    monkeypatch.setattr("core.authorization.authorize", deny)
    scanner = ActiveScanner(bus)
    scanner._checks = [FindingCheck()]

    results = await scanner.run_checks(
        {"method": "GET", "url": "https://example.com/?x=1", "headers": {}},
        ["x"],
        event={"session_id": "11111111-1111-1111-1111-111111111111"},
    )
    await asyncio.sleep(0.05)

    assert results == []
    assert skipped and skipped[0]["reason"] == "out_of_scope"
    assert skipped[0]["rule"] == "deny-example"
