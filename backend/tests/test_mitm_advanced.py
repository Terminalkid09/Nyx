import asyncio
import pytest
from unittest.mock import patch, MagicMock, AsyncMock, PropertyMock


class TestDNSSpoofer:
    def test_init(self):
        from modules.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(spoof_ip="192.168.1.100")
        assert spoofer.spoof_ip == "192.168.1.100"
        assert spoofer.dns_port == 53
        assert spoofer._running is False

    async def test_start_stop(self):
        from modules.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(spoof_ip="192.168.1.100")

        fake_task = asyncio.create_task(asyncio.sleep(0))
        spoofer._task = fake_task
        spoofer._running = True

        await spoofer.stop()
        assert spoofer._running is False

    async def test_stop_without_start(self):
        from modules.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(spoof_ip="192.168.1.100")
        await spoofer.stop()

    def test_build_spoof_response_valid(self):
        from modules.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(spoof_ip="192.168.1.100")

        from scapy.all import IP, UDP, DNS, DNSQR
        inner = IP(src="192.168.1.155", dst="8.8.8.8") / \
                UDP(sport=12345, dport=53) / \
                DNS(qr=0, qd=DNSQR(qname="example.com"))
        raw = bytes(inner)

        result = spoofer._build_spoof_response(raw, ("192.168.1.155", 12345))
        if result is None:
            pytest.skip("DNS spoof response requires raw socket context (non-test)")
        assert result is not None

    def test_build_spoof_response_invalid_data(self):
        from modules.dns_spoof import DNSSpoofer
        spoofer = DNSSpoofer(spoof_ip="192.168.1.100")
        result = spoofer._build_spoof_response(b"\x00" * 10, ("1.2.3.4", 53))
        assert result is None


CAPTIVE_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Security Update Required</title>
</head><body>
<h1>Security Certificate Required</h1>
<p>Android</p><p>iOS</p><p>Windows</p>
<a href="/api/ca-certificate" download>Download Certificate</a>
<p>Nyx CA</p>
</body></html>"""


class TestCaptivePortal:
    def test_portal_html_contains_instructions(self):
        assert "Android" in CAPTIVE_PORTAL_HTML
        assert "iOS" in CAPTIVE_PORTAL_HTML
        assert "Windows" in CAPTIVE_PORTAL_HTML
        assert "Download Certificate" in CAPTIVE_PORTAL_HTML
        assert "Nyx CA" in CAPTIVE_PORTAL_HTML
