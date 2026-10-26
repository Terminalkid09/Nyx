"""SEC-01: the AP SSID/passphrase must never reach a shell interpreter."""
import subprocess

import pytest

from modules.wifi_ap import (
    WiFiAPError,
    WiFiAPManager,
    validate_iface,
    validate_passphrase,
    validate_ssid,
)


class TestValidation:
    @pytest.mark.parametrize(
        "payload",
        [
            'x" & calc & rem "',
            "a\ninterface=eth0",
            "a\rb",
            "a\x00b",
            "",
            "x" * 33,
        ],
    )
    def test_rejects_ssid_injection(self, payload):
        with pytest.raises(ValueError):
            validate_ssid(payload)

    def test_accepts_normal_ssid(self):
        assert validate_ssid("Nyx-2.4") == "Nyx-2.4"

    @pytest.mark.parametrize(
        "payload",
        ["short", "a" * 64, 'pass"word', "pass word", "pass;rm", "pass`id`"],
    )
    def test_rejects_bad_passphrase(self, payload):
        with pytest.raises(ValueError):
            validate_passphrase(payload)

    def test_accepts_default_passphrase(self):
        assert validate_passphrase("nyxmitm2026") == "nyxmitm2026"

    def test_manager_rejects_injection(self):
        with pytest.raises(WiFiAPError):
            WiFiAPManager(ssid='x" & whoami & rem "', passphrase="nyxmitm2026")

    def test_manager_rejects_short_passphrase(self):
        with pytest.raises(WiFiAPError):
            WiFiAPManager(ssid="Nyx", passphrase="short")

    @pytest.mark.parametrize("iface", ["wlan0; rm -rf /", "wlan0 && id", "", "a" * 40])
    def test_rejects_bad_iface(self, iface):
        with pytest.raises(ValueError):
            validate_iface(iface)


class TestWindowsCommand:
    @pytest.mark.asyncio
    async def test_start_uses_argv_without_shell(self, monkeypatch):
        calls = []

        class FakeResult:
            returncode = 0

        def fake_run(*args, **kwargs):
            calls.append((args, kwargs))
            return FakeResult()

        monkeypatch.setattr(subprocess, "run", fake_run)
        manager = WiFiAPManager(ssid="Nyx", passphrase="nyxmitm2026")

        result = await manager._start_windows()

        assert result["status"] == "ok"
        assert len(calls) == 2
        for args, kwargs in calls:
            assert kwargs.get("shell") is False
            assert isinstance(args[0], list)
        assert calls[0][0][0] == [
            "netsh", "wlan", "set", "hostednetwork", "mode=allow",
            "ssid=Nyx", "key=nyxmitm2026",
        ]
        assert calls[1][0][0] == ["netsh", "wlan", "start", "hostednetwork"]
