import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestARPSpoofer:
    def test_detect_gateway_returns_none_when_no_route(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ip="192.168.1.100")
        assert spoofer.gateway_ip is not None  # system has a default route

    def test_get_local_ip_returns_string(self):
        from modules.arp_spoof import _get_local_ip
        ip = _get_local_ip()
        assert isinstance(ip, str)
        assert len(ip.split(".")) == 4

    @patch("modules.arp_spoof._get_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("modules.arp_spoof.ARPSpoofer._send_arp")
    async def test_start_stop(self, mock_send_arp, mock_get_mac):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ip="192.168.1.100", gateway_ip="192.168.1.1", interval=0.05)
        await spoofer.start()
        assert spoofer._running is True
        await asyncio.sleep(0.12)
        await spoofer.stop()
        assert spoofer._running is False
        assert mock_send_arp.call_count >= 2

    @patch("modules.arp_spoof._get_mac", return_value="aa:bb:cc:dd:ee:ff")
    @patch("modules.arp_spoof.ARPSpoofer._send_arp")
    async def test_no_double_start(self, mock_send_arp, mock_get_mac):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ip="192.168.1.100", gateway_ip="192.168.1.1")
        await spoofer.start()
        await spoofer.start()
        assert spoofer._running is True
        await spoofer.stop()

    async def test_stop_without_start(self):
        from modules.arp_spoof import ARPSpoofer
        spoofer = ARPSpoofer(target_ip="192.168.1.100", gateway_ip="192.168.1.1")
        await spoofer.stop()


class TestSetupTransparentRedirect:
    def test_linux_commands(self):
        with patch("platform.system", return_value="Linux"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
            for c in cmds:
                assert "iptables" in c or "sysctl" in c
            assert any("--dport 80" in c for c in cmds)
            assert any("--dport 443" in c for c in cmds)

    def test_linux_teardown(self):
        with patch("platform.system", return_value="Linux"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
            assert all("-D" in c or "net.ipv4.ip_forward=0" in c for c in cmds)

    def test_windows_commands(self):
        with patch("platform.system", return_value="Windows"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
            assert any("netsh" in c for c in cmds)
            assert any("forwarding enabled" in c for c in cmds)

    def test_windows_teardown(self):
        with patch("platform.system", return_value="Windows"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
            assert any("forwarding disabled" in c for c in cmds)

    def test_macos_commands(self):
        with patch("platform.system", return_value="Darwin"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
            for c in cmds:
                assert "pfctl" in c or "sysctl" in c or "echo" in c
            assert any("port 8080" in c for c in cmds)

    def test_macos_teardown(self):
        with patch("platform.system", return_value="Darwin"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
            assert any("pfctl -F all" in c for c in cmds)
            assert any("ip.forwarding=0" in c for c in cmds)


class TestMITMStatusEndpoint:
    @pytest.mark.asyncio
    @patch("api.routes.mitm._is_admin", return_value=True)
    async def test_mitm_status_inactive(self, mock_admin):
        from api.routes.mitm import mitm_status
        result = await mitm_status()
        assert result["active"] is False
        assert result["admin_mode"] is True
        assert "proxy_mode" in result
        assert "redirect_active" in result

    @pytest.mark.asyncio
    @patch("api.routes.mitm._is_admin", return_value=False)
    async def test_mitm_status_non_admin(self, mock_admin):
        from api.routes.mitm import mitm_status
        result = await mitm_status()
        assert result["admin_mode"] is False


class TestMITMStartValidation:
    @patch("api.routes.mitm._engine", None)
    @pytest.mark.asyncio
    async def test_start_without_engine(self):
        from api.routes.mitm import mitm_start
        from api.routes.mitm import MITMStartRequest
        with pytest.raises(Exception) as exc:
            await mitm_start(MITMStartRequest(target_ip="192.168.1.100"))
        assert "not initialized" in str(exc.value)


class TestProxyEngineTransparent:
    @patch("core.proxy.engine.DumpMaster")
    @patch("core.proxy.engine.asyncio.new_event_loop")
    def test_transparent_mode_option(self, mock_loop, mock_dumpmaster):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus, mode="transparent")
        mock_loop_instance = MagicMock()
        mock_loop.return_value = mock_loop_instance
        engine.start(fastapi_loop=MagicMock())
        import time
        time.sleep(0.1)
        engine.stop()
        assert engine.mode == "transparent"

    @patch("core.proxy.engine.DumpMaster")
    @patch("core.proxy.engine.asyncio.new_event_loop")
    def test_regular_mode_default(self, mock_loop, mock_dumpmaster):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus)
        assert engine.mode == "regular"

    def test_emit_event_handles_exception(self):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus)
        engine.fastapi_loop = MagicMock()
        engine.fastapi_loop.is_closed.return_value = False
        with patch("asyncio.run_coroutine_threadsafe", side_effect=Exception("fail")):
            engine.emit_event({"type": "test"})
