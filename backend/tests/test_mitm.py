import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI


class TestMITMModels:
    def test_mitm_start_request_validates_target_ips(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100", "192.168.1.101"])
        assert req.target_ips == ["192.168.1.100", "192.168.1.101"]
        assert req.gateway_ip is None
        assert req.enable_dns_spoof is True

    def test_mitm_start_request_empty_targets(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=[])
        assert req.target_ips == []

    def test_mitm_start_request_with_gateway(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100"], gateway_ip="192.168.1.1")
        assert req.gateway_ip == "192.168.1.1"

    def test_mitm_start_response_model(self):
        from api.routes.mitm import MITMStartResponse
        resp = MITMStartResponse(
            status="ok",
            message="MITM active",
            admin_mode=True,
            captive_portal_url="http://test:8000/api/mitm/portal",
        )
        assert resp.model_dump() == {
            "status": "ok",
            "message": "MITM active",
            "admin_mode": True,
            "captive_portal_url": "http://test:8000/api/mitm/portal",
        }

    def test_mitm_stop_response_model(self):
        from api.routes.mitm import MITMStopResponse
        resp = MITMStopResponse(status="ok", message="Stopped")
        assert resp.model_dump() == {"status": "ok", "message": "Stopped"}

    def test_network_device_model(self):
        from api.routes.mitm import NetworkDevice
        dev = NetworkDevice(
            ip="192.168.1.100",
            mac="aa:bb:cc:dd:ee:ff",
            hostname="test.local",
            vendor="Test Inc",
            is_local=False,
        )
        assert dev.ip == "192.168.1.100"
        assert dev.mac == "aa:bb:cc:dd:ee:ff"
        assert dev.hostname == "test.local"
        assert dev.vendor == "Test Inc"
        assert dev.is_local is False
        d = dev.model_dump(exclude_none=True)
        assert d["ip"] == "192.168.1.100"

    def test_network_device_minimal(self):
        from api.routes.mitm import NetworkDevice
        dev = NetworkDevice(ip="10.0.0.1")
        assert dev.ip == "10.0.0.1"
        assert dev.mac is None
        assert dev.vendor is None
        assert dev.is_local is False


class TestLocalIPDetection:
    def test_get_local_ip_returns_valid_ip(self):
        from modules.arp_spoof import _get_local_ip
        ip = _get_local_ip()
        parts = ip.split(".")
        assert len(parts) == 4
        assert all(p.isdigit() for p in parts)

    def test_get_local_ip_not_loopback(self):
        from modules.arp_spoof import _get_local_ip
        ip = _get_local_ip()
        assert not ip.startswith("127.")


class TestGatewayDetection:
    def test_detect_gateway_returns_ip_or_none(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"])
        if spoofer.gateway_ip:
            parts = spoofer.gateway_ip.split(".")
            assert len(parts) == 4
            assert all(p.isdigit() for p in parts)


class TestARPSpooferMultiTarget:
    def test_init_with_single_target(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"])
        assert spoofer.target_ips == ["192.168.1.100"]

    def test_init_with_multiple_targets(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100", "192.168.1.101", "192.168.1.102"])
        assert len(spoofer.target_ips) == 3
        assert "192.168.1.101" in spoofer.target_ips

    def test_init_with_custom_gateway(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"], gateway_ip="10.0.0.1")
        assert spoofer.gateway_ip == "10.0.0.1"

    def test_init_interval_default(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"])
        assert spoofer.interval == 3.0

    def test_init_custom_interval(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"], interval=5.0)
        assert spoofer.interval == 5.0


class TestMITMStatusEndpoint:
    @pytest.mark.asyncio
    async def test_mitm_status_returns_structure(self):
        from api.routes.mitm import router
        app = FastAPI()
        app.include_router(router)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/mitm/status")
        assert resp.status_code == 200
        body = resp.json()
        assert "active" in body
        assert "arp_spoofing" in body
        assert "dns_spoofing" in body
        assert "target_ips" in body
        assert "gateway_ip" in body
        assert "admin_mode" in body
        assert "proxy_mode" in body
        assert "redirect_active" in body


class TestMITMStartValidation:
    @pytest.mark.asyncio
    async def test_start_without_target_field_returns_422(self):
        from api.routes.mitm import router
        app = FastAPI()
        app.include_router(router)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/mitm/start", json={})
        assert resp.status_code == 422


class TestSetupTransparentRedirect:
    def test_linux_enable_commands(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Linux")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
        assert len(cmds) > 0
        assert any("iptables" in c for c in cmds)
        assert any("sysctl" in c for c in cmds)
        assert any("--dport 80" in c for c in cmds)
        assert any("--dport 443" in c for c in cmds)

    def test_linux_disable_commands(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Linux")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
        assert len(cmds) > 0
        assert any("-D" in c or "net.ipv4.ip_forward=0" in c for c in cmds)

    def test_windows_enable_commands(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Windows")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
        assert len(cmds) == 0

    def test_windows_disable_commands(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Windows")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
        assert len(cmds) == 0

    def test_macos_enable_commands(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Darwin")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
        assert all("pfctl" in c or "sysctl" in c or "echo" in c for c in cmds)
        assert any("port 8080" in c for c in cmds)

    def test_macos_disable_commands(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Darwin")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
        assert any("pfctl -F all" in c for c in cmds)
        assert any("ip.forwarding=0" in c for c in cmds)

    def test_redirect_port_mapping(self):
        import platform
        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(platform, "system", lambda: "Linux")
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(9090, enable=True)
        assert any("--dport 80" in c for c in cmds)
        assert any("--dport 443" in c for c in cmds)
        assert any("9090" in c for c in cmds)


class TestFirewallPersistence:
    """Stealth-mode regression: the LAN proxy firewall rule must survive a
    "Stop MITM" and only be removed at backend shutdown."""

    @pytest.mark.asyncio
    async def test_stop_keeps_firewall_rule(self):
        from unittest.mock import patch, AsyncMock, MagicMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine._master = None

        spoofer = AsyncMock()
        dns = AsyncMock()

        old_spoofer, old_dns, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = spoofer
            mitm_mod._dns_spoofer = dns
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = True

            with patch.object(mitm_mod, "_exec_admin_redirect", return_value=[]) as redirect, \
                 patch.object(mitm_mod, "_remove_windows_firewall") as rm_fw:
                await mitm_mod.mitm_stop()

            # Redirect disabled, spoofers stopped...
            redirect.assert_called_once_with(8080, enable=False)
            spoofer.stop.assert_awaited_once()
            dns.stop.assert_awaited_once()
            # ...but the firewall rule is KEPT so manual-proxy LAN devices
            # can still reach Nyx after interception is stopped.
            rm_fw.assert_not_called()
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._redirect_active = old_redirect

    @pytest.mark.asyncio
    async def test_shutdown_removes_firewall_rule(self):
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080

        spoofer = AsyncMock()
        dns = AsyncMock()

        old_spoofer, old_dns, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = spoofer
            mitm_mod._dns_spoofer = dns
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = True

            with patch.object(mitm_mod, "_exec_admin_redirect", return_value=[]), \
                 patch.object(mitm_mod, "_remove_windows_firewall") as remove_fw:
                await mitm_mod.shutdown_mitm()

            # Backend shutdown cleans up everything, including the LAN proxy rule.
            assert remove_fw.call_count == 2  # proxy port + 8082 transparent port
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._redirect_active = old_redirect


class TestMitmWarnings:
    """mitm_start must not lose warnings accumulated along the way (firewall
    failure, DNS spoof failure, non-admin, redirect not active)."""

    @pytest.mark.asyncio
    async def test_firewall_warning_not_lost(self):
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")
        fake_engine.transport_ready = True

        old_spoofer, old_dns, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = None
            mitm_mod._dns_spoofer = None
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = False

            spoofer = MagicMock()
            spoofer.gateway_ip = "192.168.1.1"

            req = mitm_mod.MITMStartRequest(
                target_ips=["192.168.1.100"],
                gateway_ip="192.168.1.1",
                enable_dns_spoof=False,
            )
            with patch.object(mitm_mod, "_is_admin", return_value=True), \
                 patch.object(mitm_mod, "platform") as plat, \
                 patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer), \
                 patch.object(spoofer, "start", new=AsyncMock()):
                plat.system.return_value = "Windows"
                with patch.object(mitm_mod, "_ensure_windows_firewall", return_value=False):
                    resp = await mitm_mod.mitm_start(req)

            assert resp.status == "ok"
            assert "Windows Firewall rule" in resp.message
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._redirect_active = old_redirect


class TestMitmTransportGuard:
    """Windows: starting spoofing without a working transparent transport must
    be refused — otherwise ARP/DNS redirect target traffic into a blackhole
    (looks like "Nyx blocks the internet") and cannot be stopped from the UI."""

    @pytest.mark.asyncio
    async def test_windows_start_refused_without_transport(self):
        from unittest.mock import patch, MagicMock, AsyncMock
        from fastapi import HTTPException
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")
        fake_engine.transport_ready = False

        old_spoofer, old_dns, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = None
            mitm_mod._dns_spoofer = None
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = False

            spoofer = MagicMock()
            req = mitm_mod.MITMStartRequest(
                target_ips=["192.168.1.100"],
                gateway_ip="192.168.1.1",
                enable_dns_spoof=True,
            )
            with patch.object(mitm_mod, "_is_admin", return_value=True), \
                 patch.object(mitm_mod, "platform") as plat, \
                 patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer):
                plat.system.return_value = "Windows"
                with pytest.raises(HTTPException) as exc:
                    await mitm_mod.mitm_start(req)
            assert exc.value.status_code == 400
            assert "Stealth Mode" in exc.value.detail
            # Spoofers must NOT have been started (no blackhole).
            assert mitm_mod._spoofer is None
            assert mitm_mod._dns_spoofer is None
            assert spoofer.start.call_count == 0
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._redirect_active = old_redirect


