"""Tests for the MITM-scoped packet feed (modules/network/mitm_feed.py).

The feed must:
- build a correct target-scoped BPF (targets + DHCP handshake)
- start/stop cleanly with mocked NetworkEngine (no real sniffer in tests)
- never raise out of start (degrade to status.error instead)
- reset its buffer/targets on stop
"""
import pytest

from modules.network import mitm_feed


class _FakeEngine:
    """Minimal NetworkEngine stand-in: no sockets, instant lifecycle."""

    instances = []

    def __init__(self, interface="auto", bpf_filter="", **kwargs):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.started = False
        self.stopped = False
        self.recent_packets = [{"seq": 1, "proto": "tcp", "src": "10.0.0.9", "dst": "1.2.3.4", "length": 60}]
        _FakeEngine.instances.append(self)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def run_async(self):
        return

    def get_packet_detail(self, seq):
        """Mirror the real engine's detail contract (None = not in buffer)."""
        return None


@pytest.fixture(autouse=True)
def _reset_feed():
    """Each test starts from a stopped feed."""
    mitm_feed._feed_engine = None
    mitm_feed._feed_task = None
    mitm_feed._feed_error = None
    mitm_feed._feed_targets = set()
    mitm_feed._feed_started_ts = None
    _FakeEngine.instances = []
    yield


@pytest.fixture
def fake_engine(monkeypatch):
    monkeypatch.setattr("modules.network.engine.NetworkEngine", _FakeEngine)
    return _FakeEngine


class TestBuildTargetBpf:
    def test_bpf_contains_all_targets(self):
        bpf = mitm_feed.build_target_bpf({"192.168.1.6", "192.168.1.60"})
        assert "host 192.168.1.6" in bpf
        assert "host 192.168.1.60" in bpf
        assert bpf.index("192.168.1.6") < bpf.index("192.168.1.60")  # sorted

    def test_bpf_includes_dhcp_ports(self):
        bpf = mitm_feed.build_target_bpf({"10.0.0.5"})
        assert "port 67" in bpf and "port 68" in bpf

    def test_bpf_without_dhcp(self):
        bpf = mitm_feed.build_target_bpf({"10.0.0.5"}, include_dhcp=False)
        assert "port 67" not in bpf

    def test_empty_targets_falls_back(self):
        # No targets -> no host terms; with DHCP kept the clause survives alone,
        # without it the BPF degrades to bare ARP.
        assert mitm_feed.build_target_bpf(set()) == "(port 67 or port 68)"
        assert mitm_feed.build_target_bpf(set(), include_dhcp=False) == "arp"


class TestFeedLifecycle:
    @pytest.mark.asyncio
    async def test_start_runs_engine_and_records_targets(self, fake_engine):
        await mitm_feed.start_feed({"192.168.1.6", "192.168.1.60"}, gateway_ip="192.168.1.1")
        assert mitm_feed._feed_engine is not None
        assert mitm_feed._feed_engine.started
        status = mitm_feed.feed_status()
        assert status["running"] is True
        assert status["targets"] == ["192.168.1.6", "192.168.1.60"]
        # Gateway must NOT be in the BPF targets (only target endpoints)
        assert "192.168.1.1" not in " ".join(status["targets"])
        await mitm_feed.stop_feed()

    @pytest.mark.asyncio
    async def test_start_with_no_targets_sets_error_not_engine(self, fake_engine):
        await mitm_feed.start_feed(set())
        assert mitm_feed._feed_engine is None
        assert mitm_feed.feed_status()["error"]

    @pytest.mark.asyncio
    async def test_start_failure_degrades_to_error(self, monkeypatch):
        class _Boom:
            def __init__(self, *a, **k):
                raise RuntimeError("Npcap missing")

        monkeypatch.setattr("modules.network.engine.NetworkEngine", _Boom)
        await mitm_feed.start_feed({"10.0.0.5"})  # must NOT raise
        status = mitm_feed.feed_status()
        assert status["running"] is False
        assert "Npcap missing" in (status["error"] or "")

    @pytest.mark.asyncio
    async def test_stop_clears_state(self, fake_engine):
        await mitm_feed.start_feed({"10.0.0.5"})
        engine = mitm_feed._feed_engine
        await mitm_feed.stop_feed()
        assert mitm_feed._feed_engine is None
        assert mitm_feed._feed_targets == set()
        assert mitm_feed.feed_status()["running"] is False
        assert engine.stopped

    @pytest.mark.asyncio
    async def test_double_start_keeps_single_engine(self, fake_engine):
        await mitm_feed.start_feed({"10.0.0.5"})
        first = mitm_feed._feed_engine
        await mitm_feed.start_feed({"10.0.0.6"})  # ignored
        assert mitm_feed._feed_engine is first
        assert len(_FakeEngine.instances) == 1
        await mitm_feed.stop_feed()


class TestRecentPackets:
    @pytest.mark.asyncio
    async def test_packets_from_engine(self, fake_engine):
        await mitm_feed.start_feed({"10.0.0.5"})
        pkts = mitm_feed.recent_packets()
        assert pkts and pkts[0]["seq"] == 1
        await mitm_feed.stop_feed()

    def test_packets_empty_when_not_running(self):
        assert mitm_feed.recent_packets() == []

    def test_limit_is_clamped(self, fake_engine):
        # limit <= 0 and > 400 must not explode (min/max clamp)
        assert isinstance(mitm_feed.recent_packets(0), list)
        assert isinstance(mitm_feed.recent_packets(10**9), list)


class TestPacketDetail:
    """The feed engine handle used by GET /api/mitm/packets/{seq}."""

    def test_feed_engine_none_when_off(self):
        assert mitm_feed.feed_engine() is None

    @pytest.mark.asyncio
    async def test_feed_engine_returns_live_engine(self, fake_engine):
        await mitm_feed.start_feed({"10.0.0.5"})
        try:
            engine = mitm_feed.feed_engine()
            assert engine is mitm_feed._feed_engine
            # The detail contract the endpoint relies on: the engine exposes
            # get_packet_detail(seq) -> dict | None (same as the Network tab).
            assert hasattr(engine, "get_packet_detail")
            assert engine.get_packet_detail(999) is None
        finally:
            await mitm_feed.stop_feed()

