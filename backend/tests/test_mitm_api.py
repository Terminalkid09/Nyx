"""API-level tests for the MITM routes.

Tests the actual HTTP endpoints: /api/mitm/status, /api/mitm/start,
/api/mitm/stop, /api/mitm/scan-network, /api/mitm/tls.
"""
import pytest
from fastapi.testclient import TestClient


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


class TestMITMStatusAPI:
    """GET /api/mitm/status"""

    def test_status_returns_200(self, client, auth_headers):
        """Status endpoint returns 200."""
        resp = client.get("/api/mitm/status", headers=auth_headers)
        assert resp.status_code == 200

    def test_status_has_required_fields(self, client, auth_headers):
        """Status response contains all required fields."""
        resp = client.get("/api/mitm/status", headers=auth_headers)
        data = resp.json()
        for field in ["active", "arp_spoofing", "ndp_spoofing", "dns_spoofing",
                       "target_ips", "gateway_ip", "admin_mode", "proxy_mode",
                       "redirect_active"]:
            assert field in data, f"missing field: {field}"

    def test_status_active_is_false_initially(self, client, auth_headers):
        """Status shows active=false when MITM is not running."""
        resp = client.get("/api/mitm/status", headers=auth_headers)
        data = resp.json()
        assert data["active"] is False

    def test_status_target_ips_is_list(self, client, auth_headers):
        """target_ips is a list."""
        resp = client.get("/api/mitm/status", headers=auth_headers)
        data = resp.json()
        assert isinstance(data["target_ips"], list)


class TestMITMStartAPI:
    """POST /api/mitm/start"""

    def test_start_without_target_ips_returns_422(self, client, auth_headers):
        """Start without target_ips returns 422 validation error."""
        resp = client.post("/api/mitm/start", json={}, headers=auth_headers)
        assert resp.status_code == 422

    def test_start_with_empty_targets_returns_error(self, client, auth_headers):
        """Start with empty target_ips returns error."""
        resp = client.post("/api/mitm/start",
                          json={"target_ips": []}, headers=auth_headers)
        # May be 422 (validation) or 400/500 (empty list handling)
        assert resp.status_code in (400, 422, 500)

    def test_start_with_invalid_ip_returns_error(self, client, auth_headers):
        """Start with invalid IP format returns error."""
        resp = client.post("/api/mitm/start",
                          json={"target_ips": ["not-an-ip"]}, headers=auth_headers)
        # May be 422 (validation) or 400/500 (invalid IP handling)
        assert resp.status_code in (400, 422, 500)

    def test_start_without_admin_returns_error(self, client, auth_headers):
        """Start without admin privileges returns error about WinDivert."""
        resp = client.post("/api/mitm/start",
                          json={"target_ips": ["192.168.1.100"]},
                          headers=auth_headers)
        # Without admin, should return error about WinDivert/admin
        assert resp.status_code in (400, 500)
        detail = resp.json().get("detail", "")
        # The wording is platform-dependent (Windows: admin/WinDivert refusal;
        # POSIX: transparent transport / event-loop unavailability) — assert
        # the behavior, not the exact message.
        assert detail, "expected a non-empty error detail"
        assert not isinstance(detail, dict), "error detail must not leak internals"


class TestMITMStopAPI:
    """POST /api/mitm/stop"""

    def test_stop_returns_200(self, client, auth_headers):
        """Stop endpoint returns 200."""
        resp = client.post("/api/mitm/stop", headers=auth_headers)
        assert resp.status_code == 200

    def test_stop_when_not_running(self, client, auth_headers):
        """Stop when MITM is not running still returns 200."""
        resp = client.post("/api/mitm/stop", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "stopped" in str(data).lower() or resp.status_code == 200


class TestMITMScanNetworkAPI:
    """GET /api/mitm/scan-network"""

    @pytest.fixture(autouse=True)
    def _no_real_network(self, monkeypatch):
        """The scan endpoint ARPs every host of a /24 (~250 probes + reverse
        DNS). Unmocked, these tests would hit the real LAN — slow (~30s each)
        and flaky; worse, after other tests have churned the default
        ThreadPoolExecutor the probes can starve and hang the whole suite.
        Stub the network layer out: the HTTP plumbing is what is under test."""
        import api.routes.mitm as mitm_mod
        monkeypatch.setattr(mitm_mod, "_get_local_ip", lambda *a, **k: "192.168.1.155")
        monkeypatch.setattr(mitm_mod, "_get_mac", lambda ip, timeout=1.5: "aa:bb:cc:dd:ee:01")
        monkeypatch.setattr(mitm_mod, "_get_hostname", lambda ip: "host-1.local")

        async def _vendor(mac, hostname=None):
            return "TestVendor"

        monkeypatch.setattr(mitm_mod, "_lookup_vendor", _vendor)

    def test_scan_network_returns_200(self, client, auth_headers):
        """Scan network endpoint returns 200."""
        resp = client.get("/api/mitm/scan-network", headers=auth_headers)
        assert resp.status_code == 200

    def test_scan_network_returns_list(self, client, auth_headers):
        """Scan network returns a list of devices."""
        resp = client.get("/api/mitm/scan-network", headers=auth_headers)
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["mac"] == "aa:bb:cc:dd:ee:01"


class TestMITMTLSAPI:
    """POST /api/mitm/tls"""

    def test_tls_endpoint_exists(self, client, auth_headers):
        """TLS endpoint exists and responds."""
        resp = client.post("/api/mitm/tls", json={}, headers=auth_headers)
        # May return 200 or 422 depending on validation
        assert resp.status_code in (200, 422)
