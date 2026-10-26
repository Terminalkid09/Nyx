"""AP Range core: the AP only serves explicitly authorized devices."""
import pytest

from modules.wifi_ap import WiFiAPError, WiFiAPManager, validate_mac_list

MAC_A = "AA:BB:CC:DD:EE:01"
MAC_B = "aa:bb:cc:dd:ee:02"


def test_validate_mac_list_normalises_and_dedupes():
    assert validate_mac_list([MAC_A, MAC_B, MAC_A]) == [MAC_A, MAC_B.upper()]


@pytest.mark.parametrize("mac", ["not-a-mac", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:GG", ""])
def test_validate_mac_list_rejects_garbage(mac):
    with pytest.raises(ValueError):
        validate_mac_list([mac])


def test_empty_allowlist_refuses_to_start():
    with pytest.raises(WiFiAPError, match="empty allowlist"):
        WiFiAPManager(ssid="Nyx", passphrase="nyxmitm2026", allowed_macs=[])


def test_scoped_hostapd_config_uses_mac_acl():
    manager = WiFiAPManager(
        ssid="Nyx", passphrase="nyxmitm2026", allowed_macs=[MAC_A]
    )
    config = manager._hostapd_config("wlan0")
    assert "macaddr_acl=1" in config
    assert "accept_mac_file=" in config
    assert f"ssid=Nyx" in config


def test_unscoped_hostapd_config_allows_all():
    manager = WiFiAPManager(ssid="Nyx", passphrase="nyxmitm2026")
    config = manager._hostapd_config("wlan0")
    assert "macaddr_acl=0" in config
    assert "accept_mac_file=" not in config


def test_scoped_dnsmasq_only_leases_known_hosts():
    manager = WiFiAPManager(
        ssid="Nyx", passphrase="nyxmitm2026", allowed_macs=[MAC_A, MAC_B]
    )
    config = manager._dnsmasq_config("wlan0")
    assert "dhcp-ignore=tag:!known" in config
    assert f"dhcp-host={MAC_A}" in config
    assert f"dhcp-host={MAC_B.upper()}" in config


def test_unscoped_dnsmasq_has_no_allowlist():
    manager = WiFiAPManager(ssid="Nyx", passphrase="nyxmitm2026")
    config = manager._dnsmasq_config("wlan0")
    assert "dhcp-ignore" not in config
    assert "dhcp-host" not in config


@pytest.mark.asyncio
async def test_windows_cannot_enforce_a_scoped_ap():
    manager = WiFiAPManager(
        ssid="Nyx", passphrase="nyxmitm2026", allowed_macs=[MAC_A]
    )
    with pytest.raises(WiFiAPError, match="Linux"):
        await manager._start_windows()


def test_mitm_start_request_accepts_and_normalises_allowlist():
    from api.routes.mitm import MITMStartRequest

    request = MITMStartRequest(
        target_ips=["192.168.1.10"],
        wifi_ap_allowed_macs=[MAC_A, MAC_B, MAC_A],
    )
    assert request.wifi_ap_allowed_macs == [MAC_A, MAC_B.upper()]


def test_mitm_start_request_rejects_empty_allowlist():
    from pydantic import ValidationError

    from api.routes.mitm import MITMStartRequest

    with pytest.raises(ValidationError, match="at least one MAC"):
        MITMStartRequest(target_ips=["192.168.1.10"], wifi_ap_allowed_macs=[])
