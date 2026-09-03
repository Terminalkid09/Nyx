"""Tests for the stealth MITM bypasses (reactive ARP, RA spoofing, WiFi AP)."""
import pytest


class TestReactiveARP:
    def test_module_imports(self):
        from modules.arp_spoof import ARPSpoofer
        assert hasattr(ARPSpoofer, "_reactive_sniffer")
        assert hasattr(ARPSpoofer, "_REACTIVE_REFILL")

    def test_default_mode_is_active(self):
        from modules.arp_spoof import ARPSpoofer
        s = ARPSpoofer(target_ips=["192.168.1.50"], gateway_ip="192.168.1.1")
        assert s.mode == "active"

    def test_reactive_mode_accepted(self):
        from modules.arp_spoof import ARPSpoofer
        s = ARPSpoofer(target_ips=["192.168.1.50"], gateway_ip="192.168.1.1", mode="reactive")
        assert s.mode == "reactive"

    def test_reactive_refill_is_long(self):
        """Reactive mode should NOT flood — refill is 30s+, vs 3s active."""
        from modules.arp_spoof import ARPSpoofer
        assert ARPSpoofer._REACTIVE_REFILL >= 30.0
        assert ARPSpoofer._REACTIVE_REFILL > ARPSpoofer._BASE_INTERVAL * 5

    def test_reactive_has_sniffer_method(self):
        from modules.arp_spoof import ARPSpoofer
        assert callable(ARPSpoofer._reactive_sniffer)


class TestRAAdvertise:
    def test_module_imports(self):
        from modules.ndp_spoof import NDPSpoofer
        assert hasattr(NDPSpoofer, "_send_ra")

    def test_send_ra_method_exists(self):
        from modules.ndp_spoof import NDPSpoofer
        assert callable(NDPSpoofer._send_ra)

    def test_linklocal_detection(self):
        from modules.ndp_spoof import _get_local_ipv6_linklocal
        # Returns None if no IPv6, or a fe80:: address — must not crash
        result = _get_local_ipv6_linklocal()
        if result:
            assert result.startswith("fe80:")
        # No assertion on None — machine may not have IPv6


class TestWiFiAP:
    def test_module_imports(self):
        from modules.wifi_ap import WiFiAPManager, WiFiAPError, is_supported
        assert WiFiAPError is not None

    def test_is_supported_returns_dict(self):
        from modules.wifi_ap import is_supported
        result = is_supported()
        assert isinstance(result, dict)
        assert "supported" in result
        assert "reason" in result

    def test_ap_manager_constructor(self):
        from modules.wifi_ap import WiFiAPManager
        mgr = WiFiAPManager(ssid="TestAP", passphrase="testpass123")
        assert mgr.ssid == "TestAP"
        assert mgr.passphrase == "testpass123"

    @pytest.mark.asyncio
    async def test_stop_without_start_is_noop(self):
        from modules.wifi_ap import WiFiAPManager
        mgr = WiFiAPManager()
        await mgr.stop()  # must not raise

    @pytest.mark.asyncio
    async def test_start_on_unsupported_platform_raises(self):
        """On Windows without hosted-network support, start should raise
        WiFiAPError (or return a dict) — never hang or crash."""
        from modules.wifi_ap import WiFiAPManager, WiFiAPError
        import platform
        mgr = WiFiAPManager()
        sys_platform = platform.system().lower()
        if sys_platform == "windows":
            # If driver lacks hosted network, expect WiFiAPError.
            # If it has it, start may succeed or fail on privileges — either
            # is fine, we only assert no hang and sane exception type.
            try:
                result = await mgr.start()
                assert isinstance(result, dict)
            except WiFiAPError:
                pass  # expected on unsupported driver
        elif sys_platform == "linux":
            # Without root, raises WiFiAPError
            try:
                await mgr.start()
            except WiFiAPError:
                pass
        else:
            with pytest.raises(WiFiAPError):
                await mgr.start()


class TestMitmRequestNewFields:
    def test_start_request_has_arp_mode(self):
        from api.routes.mitm import MITMStartRequest
        assert "arp_mode" in MITMStartRequest.model_fields
        assert MITMStartRequest.model_fields["arp_mode"].default == "reactive"

    def test_start_request_has_wifi_ap_fields(self):
        from api.routes.mitm import MITMStartRequest
        for field in ("enable_wifi_ap", "wifi_ap_ssid", "wifi_ap_passphrase"):
            assert field in MITMStartRequest.model_fields

    def test_arp_spoofer_receives_mode(self):
        """_make_arp_spoofer must pass req.arp_mode to ARPSpoofer."""
        import inspect
        from api.routes.mitm import _make_arp_spoofer
        src = inspect.getsource(_make_arp_spoofer)
        assert "mode=req.arp_mode" in src or "arp_mode" in src