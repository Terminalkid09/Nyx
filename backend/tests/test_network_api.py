"""API-level tests for the network routes.

Tests the actual HTTP endpoints: /api/network/status, /capture/start,
/capture/stop, /packets, /frames, /streams, /export.
"""
import asyncio
import threading
import time

import pytest
from fastapi.testclient import TestClient


class _StubComponent:
    """Stands in for UDPModifier / ICMPTunnelDetector / ARPSpoofDetector —
    the status route calls .status() on whatever is attached."""

    def status(self):
        return {"enabled": False}


class _StubNetworkEngine:
    """Engine stand-in for endpoint tests: never opens a real sniffer.

    The real NetworkEngine requires a capturable interface (Npcap/libpcap
    + the requested NIC present). CI runners have neither — the previous
    unmocked version passed locally on Windows and failed on ubuntu with
    a 500 from engine.start(). The HTTP plumbing is what is under test.
    """

    instances: list = []

    def __init__(self, *args, **kwargs):
        self.requested_interface = kwargs.get("interface", "")
        self.interface = self.requested_interface
        self.bpf_filter = kwargs.get("bpf_filter", "")
        self.pcap_path = None
        self.recent_packets = []
        self.recent_frames = []
        self.recent_raw_packets = []
        self.tcp_reassembler = type("R", (), {
            "get_all_streams": staticmethod(lambda: [])})()
        self.udp_tracker = type("U", (), {
            "get_all_flows": staticmethod(lambda: [])})()
        self.udp_modifier = _StubComponent()
        self.icmp_detector = _StubComponent()
        self.arp_detector = _StubComponent()
        self.quic_connections = {}
        self.interface_changes = 0
        self.started = False
        self.stopped = False
        _StubNetworkEngine.instances.append(self)

    def on_frame(self, cb):
        self._frame_cb = cb

    def on_packet(self, cb):
        self._packet_cb = cb

    def set_pcap_output(self, writer):
        self.pcap_path = getattr(writer, "path", None)

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def run_async(self):
        return

    def get_packet_list(self, limit=200):
        return []

    def get_frame_list(self, limit=200):
        return []


@pytest.fixture
def stub_engine(monkeypatch):
    """Patch NetworkEngine at its source module (the route imports it lazily
    inside the handler, so the source module namespace is what gets read) +
    reset the routes-module globals so every test starts stopped and clean."""
    import modules.network.engine as engine_module
    import api.routes.network as net_module

    monkeypatch.setattr(engine_module, "NetworkEngine", _StubNetworkEngine)
    monkeypatch.setattr(net_module, "_network_engine", None)
    monkeypatch.setattr(net_module, "_capture_task", None)
    _StubNetworkEngine.instances = []
    yield _StubNetworkEngine
    # Ensure a stopped state for whatever runs next (order-independence).
    net_module._network_engine = None


@pytest.fixture
def client():
    """Create a TestClient for the FastAPI app."""
    from main import app
    from core.api_auth import API_KEY
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def auth_headers():
    """Return headers with valid API key."""
    from core.api_auth import API_KEY
    return {"X-API-Key": API_KEY}


class TestNetworkStatusAPI:
    """GET /api/network/status"""

    def test_status_returns_running_false_when_no_engine(self, client, auth_headers):
        """Status returns running=false when no capture is active."""
        resp = client.get("/api/network/status", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["running"] is False
        assert data["packets_buffered"] == 0
        assert data["frames_buffered"] == 0
        assert data["tcp_streams"] == 0
        assert data["udp_flows"] == 0

    def test_status_has_required_fields(self, client, auth_headers):
        """Status response contains all required fields."""
        resp = client.get("/api/network/status", headers=auth_headers)
        data = resp.json()
        for field in ["running", "interface", "bpf_filter", "pcap_path",
                       "stats", "tcp_streams", "udp_flows",
                       "packets_buffered", "frames_buffered"]:
            assert field in data, f"missing field: {field}"

    def test_status_stats_has_required_keys(self, client, auth_headers):
        """Stats dict contains all required keys."""
        resp = client.get("/api/network/status", headers=auth_headers)
        stats = resp.json()["stats"]
        for key in ["pps", "bps", "active_flows", "tcp_streams", "udp_flows",
                     "bytes_total", "packets_total", "errors",
                     "by_protocol", "by_port", "timestamp"]:
            assert key in stats, f"missing stats key: {key}"


class TestCaptureStartAPI:
    """POST /api/network/capture/start"""

    def test_start_capture_returns_200(self, client, auth_headers, stub_engine):
        """Start capture returns 200 with status=started."""
        resp = client.post("/api/network/capture/start",
                          json={"interface": "Wi-Fi"}, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "started"
        assert data["interface"] == "Wi-Fi"

    def test_start_capture_missing_interface_returns_422(self, client, auth_headers):
        """Start capture without interface returns 422 validation error."""
        resp = client.post("/api/network/capture/start", json={}, headers=auth_headers)
        assert resp.status_code == 422

    def test_start_capture_twice_returns_409(self, client, auth_headers, stub_engine):
        """Starting capture twice returns 409 Conflict."""
        client.post("/api/network/capture/start",
                   json={"interface": "Wi-Fi"}, headers=auth_headers)
        resp = client.post("/api/network/capture/start",
                          json={"interface": "Wi-Fi"}, headers=auth_headers)
        assert resp.status_code == 409
        assert "already running" in resp.json()["detail"]

        # Cleanup
        client.post("/api/network/capture/stop", headers=auth_headers)

    def test_start_then_status_shows_running(self, client, auth_headers, stub_engine):
        """After starting, status shows running=True."""
        client.post("/api/network/capture/start",
                   json={"interface": "Wi-Fi"}, headers=auth_headers)
        resp = client.get("/api/network/status", headers=auth_headers)
        data = resp.json()
        assert data["running"] is True
        assert data["interface"] == "Wi-Fi"

        # Cleanup
        client.post("/api/network/capture/stop", headers=auth_headers)


class TestCaptureStopAPI:
    """POST /api/network/capture/stop"""

    def test_stop_without_start_returns_zero(self, client, auth_headers):
        """Stop without active capture returns packets_captured=0."""
        resp = client.post("/api/network/capture/stop", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["packets_captured"] == 0

    def test_start_then_stop_returns_packet_count(self, client, auth_headers):
        """Stop after start returns the number of captured packets."""
        client.post("/api/network/capture/start",
                   json={"interface": "Wi-Fi"}, headers=auth_headers)
        resp = client.post("/api/network/capture/stop", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "packets_captured" in data
        assert isinstance(data["packets_captured"], int)

    def test_stop_then_status_shows_not_running(self, client, auth_headers):
        """After stopping, status shows running=False."""
        client.post("/api/network/capture/start",
                   json={"interface": "Wi-Fi"}, headers=auth_headers)
        client.post("/api/network/capture/stop", headers=auth_headers)
        resp = client.get("/api/network/status", headers=auth_headers)
        assert resp.json()["running"] is False


class TestNetworkDataAPI:
    """GET /api/network/packets, /frames, /streams"""

    def test_packets_empty_when_no_capture(self, client, auth_headers):
        """Packets endpoint returns empty list when no capture."""
        resp = client.get("/api/network/packets", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_frames_empty_when_no_capture(self, client, auth_headers):
        """Frames endpoint returns empty list when no capture."""
        resp = client.get("/api/network/frames", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_streams_empty_when_no_capture(self, client, auth_headers):
        """Streams endpoint returns empty list when no capture."""
        resp = client.get("/api/network/streams", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_packets_has_limit_param(self, client, auth_headers):
        """Packets endpoint accepts limit parameter."""
        resp = client.get("/api/network/packets?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_frames_has_limit_param(self, client, auth_headers):
        """Frames endpoint accepts limit parameter."""
        resp = client.get("/api/network/frames?limit=10", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


class TestExportAPI:
    """GET /api/network/export"""

    def test_export_without_data_returns_404(self, client, auth_headers):
        """Export returns 404 when no packets captured."""
        resp = client.get("/api/network/export", headers=auth_headers)
        assert resp.status_code == 404

    def test_export_with_capture_returns_pcap(self, client, auth_headers, stub_engine):
        """Export returns valid pcap file after capture."""
        client.post("/api/network/capture/start",
                   json={"interface": "Wi-Fi"}, headers=auth_headers)
        client.post("/api/network/capture/stop", headers=auth_headers)

        resp = client.get("/api/network/export", headers=auth_headers)
        # May be 200 (valid pcap) or 404 (no packets buffered)
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert resp.headers["content-type"] == "application/vnd.tcpdump.pcap"


class TestStreamFramesAPI:
    """GET /api/network/streams/{stream_id}/frames"""

    def test_stream_frames_empty_when_no_capture(self, client, auth_headers):
        """Stream frames returns empty list when no capture."""
        resp = client.get("/api/network/streams/nonexistent/frames", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_stream_frames_invalid_id_returns_empty(self, client, auth_headers):
        """Stream frames with invalid ID format returns empty list."""
        resp = client.get("/api/network/streams/invalid/frames", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []


class TestPacketDetailAPI:
    """GET /api/network/packets/{seq} — Wireshark-style packet detail."""

    def test_detail_404_when_no_capture(self, client, auth_headers):
        """Detail returns 404 when no capture is active."""
        resp = client.get("/api/network/packets/1", headers=auth_headers)
        assert resp.status_code == 404

    def test_detail_returns_layer_tree_and_404_for_unknown(self, client, auth_headers, monkeypatch):
        """Known seq returns the full detail shape; unknown seq returns 404."""
        from api.routes import network as net_module

        class _StubEngine:
            def get_packet_detail(self, seq):
                if seq != 7:
                    return None
                return {
                    "seq": 7,
                    "timestamp": "2026-08-30T12:00:00",
                    "length": 74,
                    "sniffed_on": "Wi-Fi",
                    "proto": "tcp",
                    "layers": [
                        {"name": "Ethernet", "fields": {"dst": "11:22:33:44:55:66"}},
                        {"name": "IP", "fields": {"src": "10.0.0.1", "dst": "93.184.216.34"}},
                        {"name": "TCP", "fields": {"dport": {"repr": "http", "raw": 80}}},
                    ],
                    "hexdump": "0000  11 22 33 44 55 66 aa bb cc dd ee ff 08 00",
                }

        monkeypatch.setattr(net_module, "_network_engine", _StubEngine())

        resp = client.get("/api/network/packets/7", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["seq"] == 7
        assert [layer["name"] for layer in data["layers"]] == ["Ethernet", "IP", "TCP"]
        assert data["hexdump"]

        resp = client.get("/api/network/packets/999", headers=auth_headers)
        assert resp.status_code == 404

    def test_default_bpf_includes_arp_and_icmp(self):
        """The route's default BPF matches core.config's NETWORK_BPF_FILTER —
        a narrow default silently dropped ICMP/ARP the UI advertises."""
        from api.routes.network import CaptureStartRequest
        assert CaptureStartRequest.model_fields["bpf_filter"].default == \
            "tcp or udp or arp or icmp"


class _StubLiveFeed:
    """Deterministic stand-in for _LiveFeed under TestClient.

    TestClient runs every request in a short-lived event loop, so the real
    feed's tick task dies as soon as the POST returns and cross-thread
    queue.push_frame() cannot wake the endpoint. This stub:
      - preloads messages ON the endpoint's own loop (subscribe() runs inside
        the coroutine), so the endpoint never blocks waiting,
      - keeps the endpoint fed from a foreign thread via
        call_soon_threadsafe, so after the client disconnects the next
        send_json raises and the handler exits cleanly (unsubscribe fires).
    """

    def __init__(self):
        self.loop = None
        self.unsubscribed = None
        self._q = None
        self._closed = threading.Event()

    def _current_stats(self):
        from core.network.stats import StatsCollector
        return StatsCollector().get_stats(0, 0)

    def subscribe(self):
        self.loop = asyncio.get_running_loop()
        q = asyncio.Queue(maxsize=100)
        self._q = q
        # Preloaded frames the test reads — enqueued on the loop thread.
        for i in range(2):
            q.put_nowait({
                "type": "frame",
                "data": {"frame_type": f"pre{i}", "data": {}, "five_tuple": None},
            })

        def feeder():
            i = 2
            while not self._closed.is_set():
                try:
                    self.loop.call_soon_threadsafe(
                        q.put_nowait,
                        {"type": "frame", "data": {"frame_type": f"f{i}"}},
                    )
                except RuntimeError:
                    break  # loop gone
                i += 1
                time.sleep(0.02)

        threading.Thread(target=feeder, daemon=True).start()
        return q

    def unsubscribe(self, q):
        self.unsubscribed = q
        self._closed.set()


class TestWebSocketLiveAPI:
    """WS /api/network/ws/live — the frontend's real-time feed contract.

    The periodic-tick mechanics are covered deterministically in
    test_network_layer.py::TestLiveFeed (single event loop). Here we verify
    the HTTP transport contract: snapshot on connect, frame delivery, and
    queue cleanup on disconnect.
    """

    def test_snapshot_frames_and_disconnect_cleanup(self, client, monkeypatch):
        from api.routes import network as net_module

        stub = _StubLiveFeed()
        monkeypatch.setattr(net_module, "_live_feed", stub)

        with client.websocket_connect("/api/network/ws/live") as ws:
            # 1. Immediate snapshot — type stats with the full stats shape.
            snap = ws.receive_json()
            assert snap["type"] == "stats"
            for key in ["pps", "bps", "packets_total", "tcp_streams",
                        "udp_flows", "by_protocol", "by_port", "timestamp"]:
                assert key in snap["data"], f"snapshot missing key: {key}"

            # 2. Preloaded frames arrive in order (engine.on_frame path).
            m1 = ws.receive_json()
            assert m1["type"] == "frame" and m1["data"]["frame_type"] == "pre0"
            m2 = ws.receive_json()
            assert m2["data"]["frame_type"] == "pre1"

        # 3. On disconnect the subscriber queue was unsubscribed (no leak).
        assert stub.unsubscribed is stub._q
