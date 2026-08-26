import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI


class TestMITMModels:
    def test_mitm_start_request_validates_target_ips(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100", "192.168.1.101"])
        assert req.target_ips == ["192.168.1.100", "192.168.1.101"]
        assert req.gateway_ip is None
        # DNS spoofing is OFF by default (transparent ARP/DHCP already
        # intercepts; DNS-to-own-IP can blackhole the target).
        assert req.enable_dns_spoof is False
        assert req.spoof_method == "auto"

    def test_mitm_start_request_empty_targets(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=[])
        assert req.target_ips == []

    def test_mitm_start_request_with_gateway(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100"], gateway_ip="192.168.1.1")
        assert req.gateway_ip == "192.168.1.1"

    def test_mitm_start_request_enable_ndp_spoof_default(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100"])
        assert req.enable_ndp_spoof is True

    def test_mitm_start_request_enable_ndp_spoof_custom(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100"], enable_ndp_spoof=False)
        assert req.enable_ndp_spoof is False

    def test_mitm_start_request_spoof_gateway_cache_default_off(self):
        from api.routes.mitm import MITMStartRequest
        req = MITMStartRequest(target_ips=["192.168.1.100"])
        assert req.spoof_gateway_cache is False

    def test_mitm_start_response_model(self):
        from api.routes.mitm import MITMStartResponse
        resp = MITMStartResponse(
            status="ok",
            message="MITM active",
            admin_mode=True,
            session_id="11111111-1111-1111-1111-111111111111",
        )
        assert resp.model_dump() == {
            "status": "ok",
            "message": "MITM active",
            "admin_mode": True,
            "session_id": "11111111-1111-1111-1111-111111111111",
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

    def test_init_spoof_gateway_cache_default_false(self):
        """Gateway-cache poisoning is OFF by default (router detection risk)."""
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"])
        assert spoofer.spoof_gateway_cache is False

    def test_init_spoof_gateway_cache_enabled(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ips=["192.168.1.100"], spoof_gateway_cache=True)
        assert spoofer.spoof_gateway_cache is True

    def test_spoof_loop_skips_gateway_poison_by_default(self):
        """With spoof_gateway_cache=False the loop must only claim the gateway
        to the target — never claim the target to the router."""
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
        )
        assert spoofer.spoof_gateway_cache is False


class TestARPRestore:
    """The restore must claim the REAL gateway/target MACs via hwsrc.

    scapy auto-fills an unset hwsrc with the LOCAL (attacker) MAC, so a
    "restore" built like the attack packets would re-poison the target and
    newly poison the router — leaving the target blackholed after MITM stops.
    """

    GATEWAY_MAC = "11:22:33:44:55:66"
    TARGET_MAC = "aa:bb:cc:dd:ee:ff"

    @pytest.mark.asyncio
    async def test_restore_claims_real_macs(self, monkeypatch):
        from modules import arp_spoof as mod

        sent: list = []

        def fake_get_mac(ip: str, timeout: float = 1.5):
            macs = {
                "192.168.1.1": self.GATEWAY_MAC,
                "192.168.1.100": self.TARGET_MAC,
            }
            return macs[ip]

        def fake_send(pkt, **kw):
            sent.append(pkt)

        monkeypatch.setattr(mod, "_get_mac", fake_get_mac)
        monkeypatch.setattr("scapy.all.send", fake_send)

        spoofer = mod.ARPSpoofer(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
        )
        await spoofer._restore_arp()

        # 3 packets to the target + 3 packets to the router.
        assert len(sent) == 6
        to_target = [p for p in sent if p.pdst == "192.168.1.100"]
        to_router = [p for p in sent if p.pdst == "192.168.1.1"]
        assert len(to_target) == 3
        assert len(to_router) == 3
        # The target must learn the REAL router MAC — never the attacker's.
        assert all(p.hwsrc == self.GATEWAY_MAC for p in to_target)
        assert all(p.psrc == "192.168.1.1" for p in to_target)
        # The router must learn the target's OWN MAC.
        assert all(p.hwsrc == self.TARGET_MAC for p in to_router)
        assert all(p.psrc == "192.168.1.100" for p in to_router)

    @pytest.mark.asyncio
    async def test_restore_skips_when_macs_unknown(self, monkeypatch):
        from modules import arp_spoof as mod

        sent: list = []

        def fake_get_mac(ip: str, timeout: float = 1.5):
            return None

        def fake_send(pkt, **kw):
            sent.append(pkt)

        monkeypatch.setattr(mod, "_get_mac", fake_get_mac)
        monkeypatch.setattr("scapy.all.send", fake_send)

        spoofer = mod.ARPSpoofer(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
        )
        await spoofer._restore_arp()
        # Nothing is sent when the real MACs cannot be resolved (better to
        # leave the stale entry than to send a wrong "restore").
        assert sent == []


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
        assert "ndp_spoofing" in body
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


class TestTransparentTransportGuard:
    """start_transparent_transport must refuse when forwarding is not enabled
    — otherwise the spoofed target's traffic arrives at Nyx and is silently
    dropped (blackhole) while the UI still shows ACTIVE."""

    def test_transport_start_ok_when_forwarding_enabled(self, monkeypatch):
        import platform
        from core.proxy import engine as e
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        monkeypatch.setattr(e, "_start_windivert", lambda port: True)
        monkeypatch.setattr(e, "_enable_ip_forwarding", lambda: True)
        assert e.start_transparent_transport(8082) is True

    def test_transport_start_refuses_when_forwarding_fails(self, monkeypatch):
        import platform
        from core.proxy import engine as e
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        monkeypatch.setattr(e, "_start_windivert", lambda port: True)
        monkeypatch.setattr(e, "_enable_ip_forwarding", lambda: False)
        assert e.start_transparent_transport(8082) is False

    def test_transport_start_refuses_when_windivert_fails(self, monkeypatch):
        import platform
        from core.proxy import engine as e
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        monkeypatch.setattr(e, "_start_windivert", lambda port: False)
        assert e.start_transparent_transport(8082) is False


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

            # Redirect disabled (on the transparent port), spoofers stopped...
            redirect.assert_called_once_with(8082, enable=False)
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

            # Backend shutdown cleans up everything, including the LAN proxy
            # rule, the 8082 transparent port, and the DHCP UDP/67 rule.
            assert remove_fw.call_count == 3
            assert remove_fw.call_args_list[2].args[0] == 67  # DHCP rule
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
                spoof_method="arp",
            )
            with patch.object(mitm_mod, "_is_admin", return_value=True), \
                 patch.object(mitm_mod, "platform") as plat, \
                 patch.object(mitm_mod, "start_transparent_transport", return_value=True), \
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
        from unittest.mock import patch, MagicMock
        from fastapi import HTTPException
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")
        fake_engine.transport_ready = False
        fake_engine._start_error = None

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
                 patch.object(mitm_mod, "start_transparent_transport", return_value=False), \
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

    @pytest.mark.asyncio
    async def test_windows_guard_surfaces_real_cause(self):
        """When the engine failed with a real startup error (e.g. port in use),
        the guard must say so instead of the generic WinDivert guess."""
        from unittest.mock import patch, MagicMock
        from fastapi import HTTPException
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")
        fake_engine.transport_ready = False
        fake_engine._start_error = "Port 8080 is already in use. Another Nyx instance is holding it."

        old_spoofer, old_dns, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = None
            mitm_mod._dns_spoofer = None
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = False

            req = mitm_mod.MITMStartRequest(
                target_ips=["192.168.1.100"],
                gateway_ip="192.168.1.1",
                enable_dns_spoof=False,
            )
            with patch.object(mitm_mod, "_is_admin", return_value=True), \
                 patch.object(mitm_mod, "platform") as plat, \
                 patch.object(mitm_mod, "start_transparent_transport", return_value=False), \
                 patch.object(mitm_mod, "ARPSpoofer"):
                plat.system.return_value = "Windows"
                with pytest.raises(HTTPException) as exc:
                    await mitm_mod.mitm_start(req)
            assert exc.value.status_code == 400
            assert "already in use" in exc.value.detail
            assert "Stealth Mode" in exc.value.detail
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._redirect_active = old_redirect


class TestMitmTransportGuardNonWindows:
    """Linux/macOS: same blackhole guard as Windows. If iptables/pfctl port
    redirect produced no successfully-executed commands, mitm_start must
    refuse with 400 instead of silently starting a spoofing blackhole."""

    @pytest.fixture
    def env(self):
        from unittest.mock import MagicMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")

        old_spoofer, old_dns, old_ndp, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._ndp_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = None
            mitm_mod._dns_spoofer = None
            mitm_mod._ndp_spoofer = None
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = False
            yield mitm_mod, old_spoofer, old_dns, old_ndp, old_engine, old_redirect
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._ndp_spoofer = old_ndp
            mitm_mod._redirect_active = old_redirect

    @pytest.mark.asyncio
    async def test_linux_start_refused_when_redirect_fails(self, env):
        from unittest.mock import patch, MagicMock
        from fastapi import HTTPException
        mitm_mod = env[0]

        spoofer = MagicMock()
        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
            enable_dns_spoof=True,
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect", return_value=[]), \
             patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer):
            plat.system.return_value = "Linux"
            with pytest.raises(HTTPException) as exc:
                await mitm_mod.mitm_start(req)

        assert exc.value.status_code == 400
        assert "Stealth Mode" in exc.value.detail
        assert mitm_mod._spoofer is None
        assert mitm_mod._ndp_spoofer is None
        assert spoofer.start.call_count == 0

    @pytest.mark.asyncio
    async def test_macos_start_refused_when_redirect_fails(self, env):
        from unittest.mock import patch, MagicMock
        from fastapi import HTTPException
        mitm_mod = env[0]

        spoofer = MagicMock()
        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
            enable_dns_spoof=False,
            spoof_method="arp",
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect", return_value=[]), \
             patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer):
            plat.system.return_value = "Darwin"
            with pytest.raises(HTTPException) as exc:
                await mitm_mod.mitm_start(req)

        assert exc.value.status_code == 400
        assert "root" in exc.value.detail
        assert spoofer.start.call_count == 0

    @pytest.mark.asyncio
    async def test_linux_start_ok_when_redirect_succeeds(self, env):
        from unittest.mock import patch, MagicMock, AsyncMock
        mitm_mod = env[0]

        spoofer = MagicMock()
        spoofer.gateway_ip = "192.168.1.1"
        spoofer.target_ips = ["192.168.1.100"]
        spoofer.start = AsyncMock()
        dns = AsyncMock()

        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
            enable_dns_spoof=False,
            spoof_method="arp",
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect",
                          return_value=["iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT"]), \
             patch.object(mitm_mod, "_probe_target_reachability", new=AsyncMock(return_value=[])), \
             patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer), \
             patch.object(mitm_mod, "DNSSpoofer", return_value=dns):
            plat.system.return_value = "Linux"
            resp = await mitm_mod.mitm_start(req)

        assert resp.status == "ok"
        assert "ARP spoofing" in resp.message
        assert mitm_mod._redirect_active is True
        spoofer.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_macos_start_ok_when_redirect_succeeds(self, env):
        from unittest.mock import patch, MagicMock, AsyncMock
        mitm_mod = env[0]

        spoofer = MagicMock()
        spoofer.gateway_ip = "192.168.1.1"
        spoofer.target_ips = ["192.168.1.100"]
        spoofer.start = AsyncMock()

        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
            enable_dns_spoof=False,
            spoof_method="arp",
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect",
                          return_value=["echo 'rdr pass on en0 proto tcp to any port 80 -> 127.0.0.1 port 8080' | pfctl -ef -"]), \
             patch.object(mitm_mod, "_probe_target_reachability", new=AsyncMock(return_value=[])), \
             patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer):
            plat.system.return_value = "Darwin"
            resp = await mitm_mod.mitm_start(req)

        assert resp.status == "ok"
        assert "ARP spoofing" in resp.message
        spoofer.start.assert_awaited_once()


class TestNDPSpooferModule:
    def test_is_ipv6(self):
        from modules.ndp_spoof import is_ipv6
        assert is_ipv6("2001:db8::1") is True
        assert is_ipv6("fe80::1234") is True
        assert is_ipv6("192.168.1.1") is False
        assert is_ipv6("fe80::1234%eth0") is True

    def test_init_filters_ipv4_targets(self):
        from modules.ndp_spoof import NDPSpoofer
        spoofer = NDPSpoofer(target_ips=["192.168.1.100", "fe80::1", "2001:db8::5"])
        assert spoofer.target_ips == ["fe80::1", "2001:db8::5"]

    def test_init_with_custom_gateway(self):
        from modules.ndp_spoof import NDPSpoofer
        spoofer = NDPSpoofer(target_ips=["fe80::1"], gateway_ip6="fe80::1")
        assert spoofer.gateway_ip6 == "fe80::1"

    def test_solicited_node_mac(self):
        from modules.ndp_spoof import NDPSpoofer
        # 2001:db8::1 -> last 3 bytes are 0:0:1
        mac = NDPSpoofer._solicited_node_mac("2001:db8::1")
        assert mac == "33:33:ff:00:00:01"

    def test_detect_gateway_returns_none_or_ipv6(self):
        import ipaddress
        from modules.ndp_spoof import NDPSpoofer
        spoofer = NDPSpoofer(target_ips=["fe80::1"])
        gw = spoofer._detect_gateway()
        if gw:
            assert ipaddress.ip_address(gw).version == 6


class TestNDPStart:
    """IPv6 targets should drive NDPSpoofer (not ARPSpoofer) on mitm_start."""

    @pytest.fixture
    def env(self):
        from unittest.mock import MagicMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")

        old_spoofer, old_dns, old_ndp, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._ndp_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        mitm_mod._spoofer = None
        mitm_mod._dns_spoofer = None
        mitm_mod._ndp_spoofer = None
        mitm_mod._engine = fake_engine
        mitm_mod._redirect_active = False
        yield mitm_mod, old_spoofer, old_dns, old_ndp, old_engine, old_redirect
        mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
        mitm_mod._ndp_spoofer = old_ndp
        mitm_mod._redirect_active = old_redirect

    @pytest.mark.asyncio
    async def test_ipv6_targets_use_ndp_spoofer(self, env):
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.routes import mitm as mitm_mod

        ndp = MagicMock()
        ndp.gateway_ip6 = "fe80::1"
        ndp.target_ips = ["fe80::2"]
        ndp.start = AsyncMock()

        req = mitm_mod.MITMStartRequest(
            target_ips=["fe80::2"],
            gateway_ip=None,
            enable_dns_spoof=False,
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect",
                          return_value=["iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT"]), \
             patch.object(mitm_mod, "_probe_target_reachability", new=AsyncMock(return_value=[])), \
             patch.object(mitm_mod, "ARPSpoofer") as arp_cls, \
             patch.object(mitm_mod, "NDPSpoofer", return_value=ndp):
            plat.system.return_value = "Linux"
            resp = await mitm_mod.mitm_start(req)

        assert resp.status == "ok"
        assert "NDP spoofing" in resp.message
        # IPv4 spoofing must NOT have been instantiated for a pure-v6 target.
        arp_cls.assert_not_called()
        assert mitm_mod._ndp_spoofer is not None
        ndp.start.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_mixed_targets_use_both_spoofers(self, env):
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.routes import mitm as mitm_mod

        arp = MagicMock()
        arp.gateway_ip = "192.168.1.1"
        arp.target_ips = ["192.168.1.100"]
        arp.start = AsyncMock()

        ndp = MagicMock()
        ndp.gateway_ip6 = "fe80::1"
        ndp.target_ips = ["fe80::2"]
        ndp.start = AsyncMock()

        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100", "fe80::2"],
            gateway_ip=None,
            enable_dns_spoof=False,
            spoof_method="arp",
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect",
                          return_value=["iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT"]), \
             patch.object(mitm_mod, "_probe_target_reachability", new=AsyncMock(return_value=[])), \
             patch.object(mitm_mod, "ARPSpoofer", return_value=arp), \
             patch.object(mitm_mod, "NDPSpoofer", return_value=ndp):
            plat.system.return_value = "Linux"
            resp = await mitm_mod.mitm_start(req)

        assert resp.status == "ok"
        assert "ARP spoofing" in resp.message
        assert "NDP spoofing" in resp.message
        arp.start.assert_awaited_once()
        ndp.start.assert_awaited_once()


class TestApIsolationWarnings:
    """Targets that don't answer ARP/ICMP probes produce an isolation warning."""

    @pytest.mark.asyncio
    async def test_unreachable_target_produces_warning(self):
        from unittest.mock import patch, MagicMock, AsyncMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")

        old_spoofer, old_dns, old_ndp, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._ndp_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        try:
            mitm_mod._spoofer = None
            mitm_mod._dns_spoofer = None
            mitm_mod._ndp_spoofer = None
            mitm_mod._engine = fake_engine
            mitm_mod._redirect_active = False

            spoofer = MagicMock()
            spoofer.gateway_ip = "192.168.1.1"
            spoofer.target_ips = ["192.168.1.100"]
            spoofer.start = AsyncMock()

            req = mitm_mod.MITMStartRequest(
                target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
                enable_dns_spoof=False,
                spoof_method="arp",
            )
            with patch.object(mitm_mod, "_is_admin", return_value=True), \
                 patch.object(mitm_mod, "platform") as plat, \
                 patch.object(mitm_mod, "_exec_admin_redirect",
                              return_value=["iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT"]), \
                 patch.object(mitm_mod, "_probe_target_reachability",
                              new=AsyncMock(return_value=["192.168.1.100"])), \
                 patch.object(mitm_mod, "ARPSpoofer", return_value=spoofer):
                plat.system.return_value = "Linux"
                resp = await mitm_mod.mitm_start(req)

            assert resp.status == "ok"
            assert "client isolation" in resp.message
        finally:
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
            mitm_mod._ndp_spoofer = old_ndp
            mitm_mod._redirect_active = old_redirect


class TestDHCPSpoofing:
    """spoof_method routing: DHCP vs ARP vs auto-fallback."""

    @pytest.fixture
    def env(self):
        from unittest.mock import MagicMock
        from api.routes import mitm as mitm_mod

        fake_engine = MagicMock()
        fake_engine.port = 8080
        fake_engine.mode = "regular"
        fake_engine.switch_to_transparent.return_value = (True, "ok")

        old_spoofer, old_dns, old_dhcp, old_ndp, old_engine = (
            mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._dhcp_spoofer,
            mitm_mod._ndp_spoofer, mitm_mod._engine)
        old_redirect = mitm_mod._redirect_active
        mitm_mod._spoofer = None
        mitm_mod._dns_spoofer = None
        mitm_mod._dhcp_spoofer = None
        mitm_mod._ndp_spoofer = None
        mitm_mod._engine = fake_engine
        mitm_mod._redirect_active = False
        yield mitm_mod, old_spoofer, old_dns, old_dhcp, old_ndp, old_engine, old_redirect
        mitm_mod._spoofer, mitm_mod._dns_spoofer, mitm_mod._engine = old_spoofer, old_dns, old_engine
        mitm_mod._dhcp_spoofer = old_dhcp
        mitm_mod._ndp_spoofer = old_ndp
        mitm_mod._redirect_active = old_redirect

    @pytest.mark.asyncio
    async def test_dhcp_method_uses_dhcp_spoofer(self, env):
        from unittest.mock import patch, MagicMock, AsyncMock
        mitm_mod = env[0]

        dhcp = MagicMock()
        dhcp.gateway_ip = "192.168.1.50"

        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
            enable_dns_spoof=False, spoof_method="dhcp",
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect",
                          return_value=["iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT"]), \
             patch.object(mitm_mod, "_probe_target_reachability", new=AsyncMock(return_value=[])), \
             patch.object(mitm_mod, "_start_dhcp_spoofing", new=AsyncMock(return_value=dhcp)), \
             patch.object(mitm_mod, "ARPSpoofer") as arp_cls:
            plat.system.return_value = "Linux"
            resp = await mitm_mod.mitm_start(req)

        assert resp.status == "ok"
        assert "DHCP spoofing" in resp.message
        assert mitm_mod._dhcp_spoofer is dhcp
        arp_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_auto_falls_back_to_arp_when_dhcp_fails(self, env):
        from unittest.mock import patch, MagicMock, AsyncMock
        mitm_mod = env[0]

        arp = MagicMock()
        arp.gateway_ip = "192.168.1.1"
        arp.target_ips = ["192.168.1.100"]
        arp.start = AsyncMock()

        req = mitm_mod.MITMStartRequest(
            target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
            enable_dns_spoof=False, spoof_method="auto",
        )
        with patch.object(mitm_mod, "_is_admin", return_value=True), \
             patch.object(mitm_mod, "platform") as plat, \
             patch.object(mitm_mod, "_exec_admin_redirect",
                          return_value=["iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT"]), \
             patch.object(mitm_mod, "_probe_target_reachability", new=AsyncMock(return_value=[])), \
             patch.object(mitm_mod, "_start_dhcp_spoofing", new=AsyncMock(return_value=None)), \
             patch.object(mitm_mod, "ARPSpoofer", return_value=arp):
            plat.system.return_value = "Linux"
            resp = await mitm_mod.mitm_start(req)

        assert resp.status == "ok"
        assert "ARP spoofing" in resp.message
        assert "falling back to ARP" in resp.message
        assert mitm_mod._spoofer is arp
        arp.start.assert_awaited_once()


class TestARPSpooferAddTarget:
    def test_add_target_appends_and_dedupes(self):
        from modules.arp_spoof import ARPSpoofer

        spoofer = ARPSpoofer(target_ips=["192.168.1.100"])
        spoofer.add_target("192.168.1.55")
        assert spoofer.target_ips == ["192.168.1.100", "192.168.1.55"]
        spoofer.add_target("192.168.1.55")
        assert spoofer.target_ips == ["192.168.1.100", "192.168.1.55"]

    def test_last_send_ts_starts_none(self):
        from modules.arp_spoof import ARPSpoofer

        spoofer = ARPSpoofer(target_ips=["192.168.1.100"])
        assert spoofer.last_send_ts is None


class TestDHCPFallbackWatcher:
    """'auto' mode: ARP must start by itself when DHCP does not convert, and
    must NOT start when the target accepted the lease from Nyx."""

    class FakeSpoofer:
        def __init__(self):
            self.started = False
            self.target_ips = []

        async def start(self):
            self.started = True

        def add_target(self, ip):
            self.target_ips.append(ip)

    class FakeDHCPSpoofer:
        def __init__(self, offers_sent=0, lease_requests=0, granted_leases=None):
            self.offers_sent = offers_sent
            self.lease_requests = lease_requests
            self.granted_leases = granted_leases or []

    async def _run_watcher(self, monkeypatch, dhcp, target_v4, grace_no_discover=0.0, grace_race_lost=0.0):
        import asyncio
        import time

        import api.routes.mitm as mod

        calls: list = []

        async def fake_make(target, req):
            calls.append(("make", list(target)))
            sp = self.FakeSpoofer()
            await sp.start()
            return sp

        monkeypatch.setattr(mod, "_spoofer", None)
        monkeypatch.setattr(mod, "_make_arp_spoofer", fake_make)
        monkeypatch.setattr(mod, "dhcp_block_add", lambda ip: calls.append(("block", ip)))

        req = mod.MITMStartRequest(
            target_ips=target_v4, gateway_ip="192.168.1.1",
            enable_dns_spoof=False, spoof_method="auto",
        )
        task = asyncio.create_task(
            mod._dhcp_fallback_watcher(
                dhcp, target_v4, req,
                grace_no_discover=grace_no_discover,
                grace_race_lost=grace_race_lost,
                tick=0.01,
            )
        )
        deadline = time.time() + 5
        while mod._spoofer is None and time.time() < deadline:
            await asyncio.sleep(0.01)
        return task, calls

    @pytest.mark.asyncio
    async def test_arp_starts_when_no_discover(self, monkeypatch):
        import asyncio

        import api.routes.mitm as mod

        dhcp = self.FakeDHCPSpoofer(offers_sent=0, lease_requests=0)
        task, calls = await self._run_watcher(monkeypatch, dhcp, ["192.168.1.100"])
        try:
            assert mod._spoofer is not None
            assert mod._spoofer.started is True
            assert ("make", ["192.168.1.100"]) in calls
            assert ("block", "192.168.1.100") in calls
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_arp_starts_when_offer_race_lost(self, monkeypatch):
        import asyncio

        import api.routes.mitm as mod

        dhcp = self.FakeDHCPSpoofer(offers_sent=3, lease_requests=0)
        task, calls = await self._run_watcher(monkeypatch, dhcp, ["192.168.1.100"])
        try:
            assert mod._spoofer is not None
            assert mod._spoofer.started is True
            assert ("make", ["192.168.1.100"]) in calls
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    @pytest.mark.asyncio
    async def test_no_arp_when_lease_accepted(self, monkeypatch):
        import asyncio

        import api.routes.mitm as mod

        dhcp = self.FakeDHCPSpoofer(offers_sent=1, lease_requests=1)
        task, calls = await self._run_watcher(monkeypatch, dhcp, ["192.168.1.100"])
        await asyncio.wait_for(task, timeout=3)
        assert mod._spoofer is None
        assert calls == []

    @pytest.mark.asyncio
    async def test_follows_later_granted_leases_after_arp(self, monkeypatch):
        import asyncio
        import time

        import api.routes.mitm as mod

        arp = self.FakeSpoofer()
        monkeypatch.setattr(mod, "_spoofer", arp)
        dhcp = self.FakeDHCPSpoofer(
            offers_sent=1, lease_requests=1,
            granted_leases=[{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.77", "ts": 1}],
        )
        task = asyncio.create_task(
            mod._dhcp_fallback_watcher(
                dhcp, ["192.168.1.100"], mod.MITMStartRequest(
                    target_ips=["192.168.1.100"], gateway_ip="192.168.1.1",
                    enable_dns_spoof=False, spoof_method="auto",
                ),
                grace_no_discover=0.0, grace_race_lost=0.0, tick=0.01,
            )
        )
        deadline = time.time() + 3
        while "192.168.1.77" not in arp.target_ips and time.time() < deadline:
            await asyncio.sleep(0.01)
        assert "192.168.1.77" in arp.target_ips
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


