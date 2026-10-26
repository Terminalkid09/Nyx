"""The MITM status snapshot is a pure function of the current session state."""
import time

import pytest

from modules.mitm_status import activity_for_targets, build_status


class FakeSpoofer:
    def __init__(self, targets=(), gateway="10.0.0.1", running=True):
        self.target_ips = list(targets)
        self.gateway_ip = gateway
        self._running = running
        self.last_send_ts = 1_700_000_000.0


class FakeDHCP:
    def __init__(self, targets=()):
        self.granted_leases = [{"ip": ip, "mac": "aa:bb:cc:dd:ee:ff"} for ip in targets]
        self.offers_sent = 2
        self.lease_requests = 0
        self.naks_sent = 0


class FakeEngine:
    mode = "transparent"
    host = "0.0.0.0"
    port = 8080
    tls_mitm = True
    transport_ready = True

    def __init__(self, activity=()):
        self._activity = list(activity)

    def activity_snapshot(self):
        return self._activity

    def tls_failures(self):
        return 3, ["pinned.example.test"]


async def _status(**kwargs):
    base = dict(
        engine=None,
        spoofer=None,
        ndp_spoofer=None,
        dhcp_spoofer=None,
        dns_spoofer=None,
        dns_spoof_error=None,
        redirect_active=False,
        mitm_session_started_ts=None,
        dhcp_started_ts=None,
        dhcp_grace_no_discover=20.0,
        dhcp_grace_race_lost=10.0,
        admin_mode=False,
        local_ip="192.168.1.10",
    )
    base.update(kwargs)
    return await build_status(**base)


@pytest.mark.asyncio
async def test_idle_status_reports_no_session():
    status = await _status()

    assert status["active"] is False
    assert status["target_ips"] == []
    assert status["activity"] == []
    assert status["admin_mode"] is False
    assert status["proxy_mode"] is None
    assert status["captured_flows"] == 0
    assert status["ca_portal_url"] == "http://192.168.1.10:18081/"
    assert status["quic_blocked_packets"] >= 0


@pytest.mark.asyncio
async def test_loopback_is_not_advertised_as_a_proxy_host():
    status = await _status(local_ip="127.0.0.1")
    assert status["local_ip"] is None
    assert status["ca_portal_url"] is None


@pytest.mark.asyncio
async def test_running_session_exposes_every_field_the_ui_polls():
    status = await _status(
        engine=FakeEngine(activity=[{"ip": "10.0.0.5", "host": "api.example.test"}]),
        spoofer=FakeSpoofer(["10.0.0.5"]),
        dhcp_spoofer=FakeDHCP(["10.0.0.6"]),
        redirect_active=True,
        admin_mode=True,
    )

    assert status["active"] is True
    assert status["arp_spoofing"] is True
    assert status["dhcp_spoofing"] is True
    assert status["dhcp_granted_ips"] == ["10.0.0.6"]
    assert status["target_ips"] == ["10.0.0.5"]
    assert status["gateway_ip"] == "10.0.0.1"
    assert status["proxy_host"] == "0.0.0.0"
    assert status["proxy_port"] == 8080
    assert status["tls_mitm"] is True
    assert status["redirect_active"] is True
    assert status["admin_mode"] is True
    assert status["tls_handshake_failures"] == 3
    assert status["tls_failed_hosts"] == ["pinned.example.test"]
    assert status["last_arp_sent"].startswith("2023-11-14")


@pytest.mark.asyncio
async def test_activity_is_filtered_to_the_selected_targets():
    engine = FakeEngine(
        activity=[
            {"ip": "10.0.0.5", "host": "wanted.test"},
            {"ip": "10.0.0.99", "host": "leftover-cache.test"},
        ]
    )
    status = await _status(engine=engine, spoofer=FakeSpoofer(["10.0.0.5"]))

    assert [entry["host"] for entry in status["activity"]] == ["wanted.test"]


def test_activity_without_targets_shows_the_raw_snapshot():
    engine = FakeEngine(activity=[{"ip": "10.0.0.1", "host": "a.test"}])
    assert activity_for_targets(engine, None, None, None) == engine.activity_snapshot()


@pytest.mark.asyncio
async def test_dhcp_fallback_countdown_when_nobody_answers():
    dhcp = FakeDHCP()
    dhcp.offers_sent = 0  # the target never sent a DISCOVER
    status = await _status(dhcp_spoofer=dhcp, dhcp_started_ts=time.time() - 5)

    # Grace is 20s (no DISCOVER yet) and 5s have passed.
    assert 14 < status["dhcp_fallback_in"] <= 15


@pytest.mark.asyncio
async def test_fallback_uses_the_shorter_grace_when_the_offer_race_was_lost():
    dhcp = FakeDHCP()  # offers were sent but no lease was requested
    status = await _status(dhcp_spoofer=dhcp, dhcp_started_ts=time.time() - 5)

    assert 4 < status["dhcp_fallback_in"] <= 5


@pytest.mark.asyncio
async def test_dhcp_fallback_is_none_once_the_lease_is_requested():
    dhcp = FakeDHCP()
    dhcp.lease_requests = 1
    status = await _status(dhcp_spoofer=dhcp, dhcp_started_ts=time.time() - 5)

    assert status["dhcp_fallback_in"] is None
