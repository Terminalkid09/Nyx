from unittest.mock import MagicMock, patch


class TestTlsMitmGate:
    def test_gate_passthrough_when_disabled(self):
        from core.proxy.addons.tls_gate import TlsMitmGate

        gate = TlsMitmGate(enabled=False)
        data = MagicMock()
        gate.tls_clienthello(data)
        assert data.ignore_connection is True

    def test_gate_does_not_ignore_when_enabled(self):
        from core.proxy.addons.tls_gate import TlsMitmGate

        gate = TlsMitmGate(enabled=True)
        data = type("ClientHelloData", (), {"ignore_connection": False})()
        gate.tls_clienthello(data)
        assert data.ignore_connection is False


class TestProxyEngineSwitchMode:
    @patch("core.proxy.engine.DumpMaster")
    @patch("core.proxy.engine.asyncio.new_event_loop")
    def test_switch_to_transparent_already_transparent(self, mock_loop, mock_dump):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus, mode="transparent")
        result, msg = engine.switch_to_transparent()
        assert result is True
        assert engine.mode == "transparent"

    @patch("core.proxy.engine.ProxyEngine.start")
    @patch("platform.system", return_value="Linux")
    def test_switch_to_transparent_from_regular(self, mock_sys, mock_start):
        from core.proxy.engine import ProxyEngine
        mock_start.return_value = (True, "Proxy running")
        bus = MagicMock()
        engine = ProxyEngine(bus, mode="regular")
        engine.fastapi_loop = MagicMock()
        engine.stop = MagicMock()
        result, msg = engine.switch_to_transparent()
        assert result is True
        assert engine.mode == "transparent"
        engine.stop.assert_called_once()

    @patch("core.proxy.engine.DumpMaster")
    @patch("core.proxy.engine.asyncio.new_event_loop")
    @patch("platform.system", return_value="Linux")
    def test_switch_to_transparent_no_fastapi_loop(self, mock_sys, mock_loop, mock_dump):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus, mode="regular")
        engine.fastapi_loop = None
        result, msg = engine.switch_to_transparent()
        assert result is False
        assert engine.mode == "regular"

    def test_stop_sets_stopped_flag(self):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus)
        master = MagicMock()
        engine._master = master
        engine.stop()
        assert engine._stopped.is_set()
        assert engine._master is None
        master.shutdown.assert_called_once()


class TestProxyEngineEmitEvent:
    def test_emit_event_with_active_loop(self):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus)
        engine.fastapi_loop = MagicMock()
        engine.fastapi_loop.is_closed.return_value = False
        with patch("asyncio.run_coroutine_threadsafe") as mock_run:
            engine.emit_event({"type": "test"})
            mock_run.assert_called_once()

    def test_emit_event_stopped_does_nothing(self):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus)
        engine._stopped.set()
        engine.fastapi_loop = MagicMock()
        with patch("asyncio.run_coroutine_threadsafe") as mock_run:
            engine.emit_event({"type": "test"})
            mock_run.assert_not_called()

    def test_emit_event_no_loop(self):
        from core.proxy.engine import ProxyEngine
        bus = MagicMock()
        engine = ProxyEngine(bus)
        engine.fastapi_loop = None
        with patch("asyncio.run_coroutine_threadsafe") as mock_run:
            engine.emit_event({"type": "test"})
            mock_run.assert_not_called()


class TestSetupTransparentRedirectFull:
    def test_linux_tcp6_not_included(self):
        with patch("platform.system", return_value="Linux"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
            for c in cmds:
                assert c.startswith("iptables") or c.startswith("sysctl")
                assert "tcp" in c or "ip_forward" in c

    def test_windows_port_correct(self):
        with patch("platform.system", return_value="Windows"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(9090, enable=True)
            assert len(cmds) == 0

    def test_enable_returns_nonempty(self):
        with patch("platform.system", return_value="Linux"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
            assert len(cmds) > 0

    def test_disable_returns_commands(self):
        with patch("platform.system", return_value="Windows"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=False)
            assert len(cmds) == 0

    def test_macos_enable(self):
        with patch("platform.system", return_value="Darwin"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(9090, enable=True)
            assert any("pfctl" in c for c in cmds)
            assert any("sysctl" in c for c in cmds)
            assert any("9090" in c for c in cmds)
            assert all("rdr pass" in c or "sysctl" in c or "ip.forwarding=1" in c for c in cmds)

    def test_macos_disable(self):
        with patch("platform.system", return_value="Darwin"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(9090, enable=False)
            assert any("pfctl -F all" in c for c in cmds)
            assert any("ip.forwarding=0" in c for c in cmds)

    def test_unsupported_platform(self):
        with patch("platform.system", return_value="FreeBSD"):
            from core.proxy.engine import setup_transparent_redirect
            cmds = setup_transparent_redirect(8080, enable=True)
            assert cmds == []
