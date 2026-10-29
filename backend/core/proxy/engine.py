import asyncio
import logging
import os
import platform
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from core.events.bus import EventBus
from core.config import settings
from core.netports import pick_free_port

logger = logging.getLogger(__name__)

# Port where mitmproxy's *transparent* listener runs (separate from the
# regular proxy port). Transparent redirect rules (iptables/pfctl) must point
# at THIS port, not at the regular proxy port, otherwise forwarded traffic
# hits the wrong listener and nothing is intercepted.
TRANSPARENT_PORT = 8082


# Subject the Nyx CA is issued with. mitmproxy names its CA "mitmproxy"; the
# portal and docs use the same string.
_CA_SUBJECT_MATCH = "mitmproxy"
_WIN_STORES = ("CurrentUser", "LocalMachine")


def _run_powershell(script: str, timeout: float = 20) -> subprocess.CompletedProcess | None:
    """Run a PowerShell snippet without a console window, or return None.

    ``CREATE_NO_WINDOW`` keeps a console from being attached to the backend
    when it shells out, and ``-NonInteractive`` prevents a prompt (e.g. a
    certificate-consent dialog) from blocking the request forever.
    """
    if platform.system().lower() != "windows":
        return None
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("PowerShell call failed: %s", e)
        return None


def _windows_ca_counts() -> dict[str, int]:
    """Count the Nyx CA in every Windows root store, per store.

    Returns ``{}`` when the stores could not be read — callers treat that as
    "unknown", never as "not installed".
    """
    script = (
        "foreach ($store in @('CurrentUser','LocalMachine')) { "
        "$n = @(Get-ChildItem -Path \"Cert:\\$store\\Root\" -ErrorAction SilentlyContinue "
        "| Where-Object { $_.Subject -match '" + _CA_SUBJECT_MATCH + "' }).Count; "
        "\"$store=$n\" }"
    )
    result = _run_powershell(script, timeout=15)
    if result is None:
        return {}
    counts: dict[str, int] = {}
    for line in result.stdout.splitlines():
        name, _, value = line.strip().partition("=")
        if name in _WIN_STORES and value.strip().isdigit():
            counts[name] = int(value.strip())
    return counts


def _macos_ca_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for chain, label in (
        ("/Library/Keychains/System.keychain", "System"),
        ("login.keychain", "Login"),
    ):
        try:
            out = subprocess.run(
                ["security", "find-certificate", "-a", "-c", _CA_SUBJECT_MATCH, chain],
                capture_output=True, text=True, timeout=15,
            )
            present = "mitmproxy" in (out.stdout + out.stderr).lower()
            counts[label] = 1 if present else 0
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug("CA trust check (macOS %s) failed: %s", label, e)
    return counts


def _linux_ca_files() -> list:
    dirs = [Path("/usr/local/share/ca-certificates"), Path("/etc/ssl/certs")]
    found = []
    for d in dirs:
        try:
            if not d.exists():
                continue
            for p in d.iterdir():
                if p.is_file() and (_CA_SUBJECT_MATCH in p.name.lower() or "nyx" in p.name.lower()):
                    found.append(p)
        except OSError as e:
            logger.debug("CA trust check (Linux %s) failed: %s", d, e)
    return found


def ca_trust_state() -> dict:
    """Where the Nyx/mitmproxy CA is trusted on THIS machine.

    ``trusted`` is ``None`` when the platform could not be queried: a caller
    must not read that as "not installed". Installing the CA on the operator
    machine is optional — it is only needed to browse through Nyx from this
    PC, while targets install it from the LAN portal.
    """
    system = platform.system().lower()
    if system == "windows":
        counts = _windows_ca_counts()
        if not counts:
            return {
                "platform": system, "trusted": None, "inconclusive": True,
                "stores": {}, "detail": "Could not read the Windows certificate stores.",
            }
        return {
            "platform": system,
            "trusted": any(counts.values()),
            "inconclusive": False,
            "stores": counts,
            "detail": "Root stores queried: CurrentUser (this user) and LocalMachine (this PC).",
        }
    if system == "darwin":
        counts = _macos_ca_counts()
        if not counts:
            return {
                "platform": system, "trusted": None, "inconclusive": True,
                "stores": {}, "detail": "Could not read the macOS keychains.",
            }
        return {
            "platform": system,
            "trusted": any(counts.values()),
            "inconclusive": False,
            "stores": counts,
            "detail": "Keychains queried: System and login.",
        }
    if system == "linux":
        files = _linux_ca_files()
        return {
            "platform": system,
            "trusted": bool(files),
            "inconclusive": False,
            "stores": {"System": len(files)},
            "detail": "Files under /usr/local/share/ca-certificates and /etc/ssl/certs.",
        }
    return {
        "platform": system, "trusted": None, "inconclusive": True,
        "stores": {}, "detail": f"Unsupported platform: {system}",
    }


def _ca_in_trust_store(ca_path: str | Path | None = None) -> bool:
    """True when the CA is trusted somewhere on this machine.

    Kept for callers that only need a boolean; "unknown" counts as True so an
    undetectable platform never silently disables TLS interception.
    """
    state = ca_trust_state()
    return True if state["trusted"] is None else bool(state["trusted"])


def remove_ca_verified() -> dict:
    """Remove the Nyx/mitmproxy CA everywhere we can see it, then verify.

    Verification is the point: the previous implementation reported success
    after a best-effort delete, so a CA left in the LocalMachine hive (no
    admin) or a half-finished PowerShell run looked like a clean removal. This
    returns per-store counts before/after and only sets ``removed`` when a
    fresh query finds nothing.

    Note: Windows stores are the only trust store checked here. Firefox (its
    own NSS store) and Java keystores are separate and are reported, not
    touched.
    """
    system = platform.system().lower()
    result: dict = {
        "platform": system,
        "removed": False,
        "still_present": [],
        "stores": {},
        "message": "",
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if system == "windows":
        before = _windows_ca_counts()
        if not before:
            result["message"] = (
                "Could not read the Windows certificate stores, so removal could "
                "not be verified. Check with certmgr.msc."
            )
            return result
        script = (
            "foreach ($store in @('CurrentUser','LocalMachine')) { "
            "try { "
            "$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $store); "
            "$s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite); "
            "@($s.Certificates | Where-Object { $_.Subject -match '" + _CA_SUBJECT_MATCH + "' }) "
            "| ForEach-Object { $s.Remove($_) }; "
            "$s.Close() "
            "} catch { \"ERROR $store $($_.Exception.Message)\" } }"
        )
        _run_powershell(script, timeout=30)
        after = _windows_ca_counts()
        result["stores"] = {
            name: {"before": before.get(name), "after": after.get(name)}
            for name in before
        }
        if not after:
            result["message"] = (
                "Removal ran but the stores could not be re-read, so it is NOT "
                "verified. Check with certmgr.msc."
            )
            return result
        still = [name for name, count in after.items() if count]
        result["still_present"] = still
        result["removed"] = not still
        if still:
            result["message"] = (
                "CA still present in " + ", ".join(still) + ". Removing it from "
                "LocalMachine needs Nyx running as Administrator; otherwise open "
                "certmgr.msc (Trusted Root Certification Authorities → Certificates) "
                "and delete the mitmproxy entry."
            )
        else:
            result["message"] = (
                "Nyx/mitmproxy CA removed and verified: no entry left in the "
                "CurrentUser or LocalMachine root store."
            )
        return result

    if system == "darwin":
        for chain in ("/Library/Keychains/System.keychain", "login.keychain"):
            try:
                subprocess.run(
                    ["security", "delete-certificate", "-c", _CA_SUBJECT_MATCH, chain],
                    capture_output=True, text=True, timeout=15,
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                logger.warning("CA removal failed on %s: %s", chain, e)
        after = _macos_ca_counts()
        result["stores"] = {name: {"after": count} for name, count in after.items()}
        still = [name for name, count in after.items() if count]
        result["still_present"] = still
        result["removed"] = bool(after) and not still
        result["message"] = (
            "Nyx/mitmproxy CA removed and verified from the System and login keychains."
            if result["removed"] else
            "CA still present in " + (", ".join(still) or "an unreadable keychain") +
            ". Remove it from Keychain Access."
        )
        return result

    if system == "linux":
        files = _linux_ca_files()
        removed = 0
        for p in files:
            try:
                p.unlink()
                removed += 1
            except OSError as e:
                logger.warning("Could not remove %s: %s", p, e)
        if removed:
            try:
                subprocess.run(
                    ["update-ca-certificates"],
                    capture_output=True, text=True, timeout=60,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                logger.warning("update-ca-certificates failed: %s", e)
        after = _linux_ca_files()
        result["stores"] = {"System": {"before": len(files), "after": len(after)}}
        result["still_present"] = ["System"] if after else []
        result["removed"] = not after
        result["message"] = (
            f"Nyx/mitmproxy CA removed and verified ({removed} file(s), bundle refreshed)."
            if result["removed"] else
            "CA files are still present (a root-owned directory needs sudo)."
        )
        return result

    result["message"] = f"Unsupported platform: {system}"
    return result


def remove_ca_from_trust_store() -> tuple[bool, str]:
    """Backwards-compatible wrapper around :func:`remove_ca_verified`."""
    outcome = remove_ca_verified()
    return bool(outcome["removed"]), outcome["message"]


def _linux_default_iface() -> str:
    """Detect the interface holding the default route (e.g. wlan0/enp3s0).

    Hardcoding ``eth0`` silently breaks on most modern systems. Fall back to
    ``eth0`` only if detection fails.
    """
    try:
        out = subprocess.check_output(
            "ip route show default", shell=True, timeout=5,
        ).decode("utf-8", errors="replace")
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == "default" and "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception as e:
        logger.debug("Default-route interface detection failed: %s", e)
    return "eth0"


def _setup_linux(proxy_port: int, enable: bool) -> list[str]:
    iface = _linux_default_iface()
    if enable:
        return [
            f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port {proxy_port}",
            f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {proxy_port}",
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv6.conf.all.forwarding=1",
        ]
    return [
        f"iptables -t nat -D PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port {proxy_port}",
        f"iptables -t nat -D PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {proxy_port}",
        "sysctl -w net.ipv4.ip_forward=0",
        "sysctl -w net.ipv6.conf.all.forwarding=0",
    ]


def _setup_windows(proxy_port: int, enable: bool) -> list[str]:
    if enable:
        _enable_ip_forwarding()
    return []


def _setup_macos(proxy_port: int, enable: bool) -> list[str]:
    if enable:
        return [
            f"echo 'rdr pass on en0 proto tcp from any to any port 80 -> 127.0.0.1 port {proxy_port}' | pfctl -ef -",
            f"echo 'rdr pass on en0 proto tcp from any to any port 443 -> 127.0.0.1 port {proxy_port}' | pfctl -ef -",
            "sysctl -w net.inet.ip.forwarding=1",
            "sysctl -w net.inet6.ip6.forwarding=1",
        ]
    return [
            "pfctl -F all -f /etc/pf.conf",
            "sysctl -w net.inet.ip.forwarding=0",
            "sysctl -w net.inet6.ip6.forwarding=0",
    ]


_PLATFORM_SETUP = {
    "linux": _setup_linux,
    "windows": _setup_windows,
    "darwin": _setup_macos,
}


def setup_transparent_redirect(proxy_port: int, enable: bool = True) -> list[str]:
    sys = platform.system().lower()
    setup_fn = _PLATFORM_SETUP.get(sys)
    if setup_fn is None:
        logger.warning("Unsupported platform for transparent redirect: %s", sys)
        return []
    return setup_fn(proxy_port, enable)


def _port_in_use(port: int) -> bool:
    """Check whether a TCP listener would fail to bind on ``port``.

    Binds WITHOUT SO_REUSEADDR — exactly like mitmproxy's own listener — so
    this reproduces the conflict mitmproxy will hit (on Windows, SO_REUSEADDR
    would let the probe "succeed" even when the port is taken). Used as a
    pre-flight check so a second Nyx instance (or a leftover backend) fails
    loudly at startup instead of reporting "ready" with a dead listener,
    which turns MITM into a blackhole.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Windows lets a plain bind steal a port another process holds with
        # SO_REUSEADDR on a different address (127.0.0.1 vs 0.0.0.0), so the
        # probe must ask for exclusive use to see the real conflict.
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind(("0.0.0.0", port))
        s.close()
        return False
    except OSError:
        return True
    except Exception:
        # Inconclusive (weird platform) — assume free, mitmproxy will surface
        # a real bind failure and the log watcher records it.
        return False


def _check_win_divert() -> bool:
    """Check if WinDivert is available and can be opened (on NETWORK_FORWARD layer).

    We use NETWORK_FORWARD (not NETWORK) so that traffic *forwarded* from other
    LAN devices (the whole point of MITM) is captured. NETWORK only intercepts
    packets originating from/destined to this machine.
    """
    if platform.system().lower() != "windows":
        return False
    try:
        import pydivert
        # NETWORK_FORWARD captures traffic routed through this machine from
        # other hosts — required for transparent MITM interception.
        w = pydivert.WinDivert("tcp.DstPort == 1", pydivert.Layer.NETWORK_FORWARD)
        w.open()
        w.close()
        logger.info("WinDivert check OK (NETWORK_FORWARD layer)")
        return True
    except PermissionError:
        logger.warning("WinDivert requires admin privileges — run Nyx as Administrator")
        return False
    except FileNotFoundError as e:
        logger.warning("WinDivert DLL not found: %s — rebuild backend with PyInstaller to bundle it", e)
        return False
    except Exception as e:
        logger.warning("WinDivert check failed: %s", e)
        return False


def _ip_forwarding_interface_count() -> int:
    """How many IPv4 interfaces currently have forwarding enabled (Windows)."""
    if platform.system().lower() != "windows":
        return -1
    try:
        check = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetIPInterface -AddressFamily IPv4 | "
             "Where-Object { $_.Forwarding -eq 'Enabled' }).Count"],
            capture_output=True, text=True, timeout=15
        )
        try:
            return int(check.stdout.strip() or "0")
        except ValueError:
            return 0
    except Exception as e:
        logger.debug("Could not read IP forwarding state: %s", e)
        return 0


def _set_ip_forwarding(enable: bool) -> bool:
    """Enable/disable IPv4 forwarding on Windows and VERIFY the result.

    The previous code filtered with ``InterfaceType -in @(6, 71)`` to only
    touch Ethernet/Wi-Fi. On many Windows installs (including this one)
    ``InterfaceType`` is empty/null, so the filter matched ZERO interfaces:
    ``Set-NetIPInterface`` returned rc=0 (success) while enabling forwarding
    on nothing. The target's spoofed traffic then arrived at Nyx but Windows
    silently DROPPED it (no forwarding) — the ARP blackhole that looked like
    "Nyx blocks the internet".

    IP forwarding only affects packets addressed to OTHER hosts; it does not
    disturb the PC's own inbound/outbound traffic (that earlier slowdown was
    WinDivert's RedirectLocal hijacking local traffic, fixed separately with
    local=False). So we safely enable it on ALL IPv4 interfaces and then
    verify that at least one interface actually flipped.
    """
    if platform.system().lower() != "windows":
        return False
    action = "Enabled" if enable else "Disabled"
    try:
        ps_cmd = (
            "Get-NetIPInterface -AddressFamily IPv4 "
            f"| Set-NetIPInterface -Forwarding {action}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            logger.warning(
                "PowerShell IP forwarding %s failed (rc=%d): %s",
                action.lower(), result.returncode, result.stderr.strip()[:200]
            )
            return False
    except Exception as e:
        logger.warning("PowerShell IP forwarding failed: %s", e)
        return False

    count = _ip_forwarding_interface_count()
    if enable:
        if count > 0:
            logger.info("IP forwarding enabled — %d IPv4 interface(s) now forwarding", count)
            return True
        logger.warning(
            "Set-NetIPInterface reported success but 0 interfaces are forwarding "
            "— target traffic will be dropped (blackhole)"
        )
        return False
    logger.info("IP forwarding disabled on IPv4 interfaces")
    return True


def _enable_ip_forwarding() -> bool:
    """Enable IPv4 forwarding on Windows so forwarded packets reach WinDivert."""
    return _set_ip_forwarding(True)


def _disable_ip_forwarding() -> bool:
    """Disable IPv4 forwarding on Windows when MITM stops."""
    return _set_ip_forwarding(False)


def _clear_windows_system_proxy() -> None:
    """Remove any system-level proxy settings set by mitmproxy on Windows.

    When mitmproxy is run in transparent mode and then stopped, it sometimes
    leaves the Windows system proxy (HKCU Internet Settings) pointing at
    127.0.0.1:PORT — causing all subsequent HTTP traffic from browsers /
    OpenCode / etc. to silently fail (the proxy port is closed).
    This helper clears those settings unconditionally on shutdown.
    """
    if platform.system().lower() != "windows":
        return
    try:
        ps_cmd = (
            'Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" '
            '-Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue; '
            'Remove-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" '
            '-Name ProxyServer -ErrorAction SilentlyContinue'
        )
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=10,
        )
        logger.info("Cleared Windows system proxy settings")
    except Exception as e:
        logger.debug("Could not clear Windows system proxy: %s", e)


_windivert_proxifier: Any = None
_WINDIVERT_PROXY_PORT: int = 0
_WINDIVERT_LAST_ERROR: str | None = None
# How many forwarded packets WinDivert has captured since it started. This is
# the single most useful MITM diagnostic: if it stays 0 while a target is
# poisoned, the target's traffic never reached Nyx (AP isolation, Android
# self-defence, or forwarding not enabled) — interception is impossible no
# matter what the proxy does.
_WINDIVERT_FORWARDED_COUNT: int = 0
# Timestamp (time.time) of the last forwarded packet captured by WinDivert.
# Lets the UI distinguish "target traffic is reaching Nyx but nothing decrypts
# (CA not trusted / QUIC / pinning)" from "no traffic at all".
_WINDIVERT_LAST_FORWARDED_TS: float | None = None

# Target IPs whose DHCP RENEWAL packets (udp 68 -> 67, forwarded through Nyx
# while ARP is active) must be DROPPED. Without this the target renews its old
# lease directly with the real router and never broadcasts a fresh DISCOVER;
# dropping forces it into REBINDING, where the rogue DHCP server NAKs it back
# to a DISCOVER Nyx can answer. Only forwarded traffic is affected (unicast
# renewals to the router pass through Nyx only while the target's ARP cache is
# poisoned) — broadcast DISCOVERs reach the DHCP socket normally.
_DHCP_BLOCK_TARGETS: set[str] = set()


def dhcp_block_add(target_ip: str):
    """Start dropping the target's DHCP renewals (68->67)."""
    if target_ip:
        _DHCP_BLOCK_TARGETS.add(target_ip)


def dhcp_block_remove(target_ip: str):
    _DHCP_BLOCK_TARGETS.discard(target_ip)


def dhcp_block_clear():
    _DHCP_BLOCK_TARGETS.clear()


# ── QUIC/HTTP3 blocking ──────────────────────────────────────────────────────
# Browsers and apps increasingly speak QUIC (UDP/443), which the transparent
# TCP redirect never captures — traffic silently bypasses interception. The
# fix is to DROP the target's UDP/443 packets: QUIC clients detect the dead
# path and fall back to TCP/TLS, which IS intercepted. Only packets from the
# current targets are dropped; the rest of the network is untouched.
_QUIC_BLOCK_TARGETS: set[str] = set()
_QUIC_DROPPED_COUNT = 0


def quic_block_set_targets(targets: set[str]):
    global _QUIC_DROPPED_COUNT
    _QUIC_BLOCK_TARGETS.clear()
    _QUIC_BLOCK_TARGETS.update(t for t in targets if t)
    _QUIC_DROPPED_COUNT = 0


def quic_block_clear():
    global _QUIC_DROPPED_COUNT
    _QUIC_BLOCK_TARGETS.clear()
    _QUIC_DROPPED_COUNT = 0


def quic_dropped_count() -> int:
    return _QUIC_DROPPED_COUNT


def _should_drop_quic(packet) -> bool:
    """True when this forwarded packet is one of our targets' QUIC flows."""
    return (
        bool(_QUIC_BLOCK_TARGETS)
        and packet.protocol == 17
        and packet.dst_port == 443
        and packet.src_addr in _QUIC_BLOCK_TARGETS
    )


def windivert_last_error() -> str | None:
    """Human-readable reason for the last WinDivert failure (None if none)."""
    return _WINDIVERT_LAST_ERROR


def windivert_forwarded_count() -> int:
    """Packets captured at the NETWORK_FORWARD layer (target traffic reaching Nyx)."""
    return _WINDIVERT_FORWARDED_COUNT


def windivert_last_forwarded() -> float | None:
    """time.time() of the last forwarded packet captured (None if none yet)."""
    return _WINDIVERT_LAST_FORWARDED_TS


def _stop_windivert():
    """Stop WinDivert if it was started."""
    global _windivert_proxifier, _WINDIVERT_PROXY_PORT
    if _windivert_proxifier is not None:
        try:
            _windivert_proxifier.shutdown()
            # mitmproxy's shutdown() stops serve_forever but leaves the API
            # server socket bound (it never calls server_close) — port 8085
            # stays in LISTEN inside our own process, so the next MITM start
            # sees a "foreign" API there and refuses. Close it explicitly.
            api = getattr(_windivert_proxifier, "api", None)
            if api is not None:
                api.server_close()
            logger.info("WinDivert stopped")
        except Exception as e:
            logger.warning("WinDivert shutdown error: %s", e)
        _windivert_proxifier = None
        _WINDIVERT_PROXY_PORT = 0


def _start_windivert(proxy_port: int) -> bool:
    """Start WinDivert manually to redirect forwarded traffic to the proxy."""
    global _windivert_proxifier, _WINDIVERT_PROXY_PORT, _WINDIVERT_LAST_ERROR
    _WINDIVERT_LAST_ERROR = None
    if platform.system().lower() != "windows":
        return False
    try:
        from mitmproxy.platform.windows import TransparentProxy as TP
        from mitmproxy.platform.windows import REDIRECT_API_PORT, REDIRECT_API_HOST

        if _windivert_proxifier is not None:
            if _WINDIVERT_PROXY_PORT == proxy_port:
                logger.info("WinDivert already running for port %d", proxy_port)
                return True
            _stop_windivert()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        already_running = s.connect_ex((REDIRECT_API_HOST, REDIRECT_API_PORT)) == 0
        s.close()

        if already_running and _windivert_proxifier is None:
            # The API belongs to ANOTHER process (a second Nyx instance or a
            # leftover backend). Trusting it would redirect the target's
            # traffic to a proxy whose client/server map lives in a different
            # process — the connection dies there = blackhole. Refuse loudly.
            _WINDIVERT_LAST_ERROR = (
                f"WinDivert API on port {REDIRECT_API_PORT} is already running "
                "but was NOT started by this process — another Nyx instance "
                "is active. Close all other Nyx windows and retry."
            )
            logger.error("%s", _WINDIVERT_LAST_ERROR)
            return False

        # local=False: mitmproxy's TransparentProxy by default ALSO hijacks the
        # PC's own outgoing traffic (RedirectLocal on the NETWORK layer, only
        # exempting the proxy process itself). For device interception we only
        # want traffic *forwarded* from ARP/DHCP-poisoned targets; redirecting
        # local browsers/apps through the proxy makes the whole PC slow and
        # breaks apps that don't trust the Nyx CA. forward=True keeps the
        # forwarded (target) traffic captured.
        global _WINDIVERT_FORWARDED_COUNT
        _WINDIVERT_FORWARDED_COUNT = 0
        global _WINDIVERT_LAST_FORWARDED_TS
        _WINDIVERT_LAST_FORWARDED_TS = None
        proxifier = TP(proxy_port=proxy_port, local=False, forward=True)
        # Wrap the NETWORK_FORWARD capture handler to count every forwarded
        # packet. This is the diagnostic that tells us whether a poisoned
        # target's traffic actually reaches this machine (0 = it doesn't).
        if proxifier.forward is not None:
            _orig_handle = proxifier.forward.handle

            def _counting_handle(packet):
                global _WINDIVERT_FORWARDED_COUNT
                global _WINDIVERT_LAST_FORWARDED_TS
                global _QUIC_DROPPED_COUNT
                # Drop the target's DHCP renewals to the real router (see
                # _DHCP_BLOCK_TARGETS). The packet is dropped BEFORE the
                # count/forward so the router never sees the renewal.
                if _DHCP_BLOCK_TARGETS and packet.protocol == 17:
                    if (
                        packet.src_port == 68
                        and packet.dst_port == 67
                        and packet.src_addr in _DHCP_BLOCK_TARGETS
                    ):
                        return
                # QUIC/HTTP3 block: drop the target's UDP/443 so clients fall
                # back to interceptable TCP/TLS (see _QUIC_BLOCK_TARGETS).
                if _should_drop_quic(packet):
                    _QUIC_DROPPED_COUNT += 1
                    return
                _WINDIVERT_FORWARDED_COUNT += 1
                _WINDIVERT_LAST_FORWARDED_TS = time.time()
                if _WINDIVERT_FORWARDED_COUNT <= 5:
                    logger.info(
                        "WinDivert captured forwarded pkt %s:%s -> %s:%s",
                        packet.src_addr, packet.src_port,
                        packet.dst_addr, packet.dst_port,
                    )
                elif _WINDIVERT_FORWARDED_COUNT % 200 == 0:
                    logger.info(
                        "WinDivert forwarded-packet count: %d",
                        _WINDIVERT_FORWARDED_COUNT,
                    )
                return _orig_handle(packet)

            proxifier.forward.handle = _counting_handle
        proxifier.start()
        _windivert_proxifier = proxifier
        _WINDIVERT_PROXY_PORT = proxy_port
        logger.info(
            "WinDivert started with proxy_port=%d, API on port 8085 "
            "(forwarded traffic only — local PC traffic is NOT hijacked)",
            proxy_port,
        )
        return True
    except PermissionError:
        _WINDIVERT_LAST_ERROR = "WinDivert requires Administrator privileges"
        logger.warning("%s", _WINDIVERT_LAST_ERROR)
        return False
    except FileNotFoundError as e:
        _WINDIVERT_LAST_ERROR = f"WinDivert DLL not found: {e}"
        logger.warning("%s", _WINDIVERT_LAST_ERROR)
        return False
    except Exception as e:
        _WINDIVERT_LAST_ERROR = f"WinDivert start failed: {e}"
        logger.warning("%s", _WINDIVERT_LAST_ERROR)
        return False


class _BindErrorWatcher:
    """Addon that turns mitmproxy's bind failure into a loud engine error.

    mitmproxy binds its listeners inside ``master.run()``; when the port is
    already taken (second Nyx instance, leftover backend) it logs
    "HTTP(S) proxy failed to listen ..." and keeps running with a dead
    listener. Without this watcher the engine would report "ready" and MITM
    would blackhole targets.
    """

    def __init__(self, engine):
        self.engine = engine

    def log(self, entry):
        try:
            if entry.level == "error" and "failed to listen" in entry.msg:
                self.engine._start_error = (
                    f"Proxy could not bind its listener: {entry.msg.strip()} "
                    "Another Nyx instance is probably holding the port — "
                    "close all other Nyx windows and restart."
                )
                self.engine.transport_ready = False
        except Exception:
            pass


def start_transparent_transport(proxy_port: int) -> bool:
    """Bring up the Windows transparent transport (WinDivert + IP forwarding).

    Idempotent: safe to call on every MITM start (WinDivert already running
    for the same port is a no-op). Returns True when forwarded traffic will
    actually reach the transparent proxy.

    Fails (returns False) when IP forwarding could not be enabled: without
    it, the spoofed target's traffic arrives at Nyx and Windows silently
    drops it — an immediate blackhole. Refusing here lets the caller abort
    the MITM start instead of blocking the target's internet.
    """
    if platform.system().lower() != "windows":
        return True
    if not _start_windivert(proxy_port):
        return False
    if not _enable_ip_forwarding():
        logger.error(
            "IP forwarding could not be enabled — refusing to start the "
            "transparent transport (forwarded target traffic would be "
            "silently dropped = blackhole)"
        )
        return False
    return True


def stop_transparent_transport():
    """Tear down WinDivert + IP forwarding so the PC's own traffic is untouched.

    Called on MITM stop: without it, WinDivert keeps redirecting forwarded
    (and previously local) traffic to the proxy and IP forwarding stays
    enabled — which makes the PC's own apps slow/break until Nyx is closed.
    """
    if platform.system().lower() != "windows":
        return
    _stop_windivert()
    _disable_ip_forwarding()


def _fix_win_divert_port(proxy_port: int):
    """Monkey-patch TransparentProxy.setup so Resolver finds API already running."""
    if platform.system().lower() != "windows":
        return
    try:
        from mitmproxy.platform.windows import TransparentProxy as TP

        def _patched_setup():
            pass

        TP.setup = _patched_setup
        logger.info("Monkey-patched TransparentProxy.setup to no-op (WinDivert already started)")
    except Exception as e:
        logger.warning("Failed to patch TransparentProxy: %s", e)


class ProxyEngine:
    def __init__(self, event_bus: EventBus, host="127.0.0.1", port=8080, mode="regular"):
        self.event_bus = event_bus
        self.host = host
        self.port = port
        self.mode = mode
        self.capture_active = True
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: DumpMaster | None = None
        self._tls_fail_tracker: "TlsFailTracker | None" = None
        self._activity_tracker = None
        self.fastapi_loop: asyncio.AbstractEventLoop | None = None
        self.current_session_id = None
        self._stopped = threading.Event()
        self._addons: list = []
        self._start_error: str | None = None
        # Set once the proxy thread has finished its startup phase (master
        # created and bound, or startup error) — lets callers wait for a
        # definitive transport status instead of racing the proxy thread.
        self._startup_done = threading.Event()
        self.tls_mitm: bool = True
        # Whether the *transparent* transport is actually working (WinDivert
        # running on Windows, transparent mode loaded in mitmproxy). This is
        # NOT assumed by intent: it only becomes True when the machinery
        # really started. False here means traffic will not reach the proxy
        # automatically and the UI should suggest manual proxy (Stealth).
        self.transport_ready: bool = False

    def register_addon(self, addon):
        self._addons.append(addon)

    def _preflight_ports(self) -> str | None:
        """Decide where to listen before mitmproxy binds.

        Our listener port can be taken by an unrelated process (a dev server,
        another tool) or by a dying Nyx instance. Moving one port up is always
        better than refusing to start the whole app, so the engine falls back
        automatically and keeps ``settings.PROXY_PORT`` in sync — the firewall
        rules, the PAC file and the UI all read it.

        Returns an error message when no usable configuration exists.
        """
        if _port_in_use(self.port):
            replacement = pick_free_port(self.port + 1, host=self.host or "127.0.0.1")
            if replacement == self.port:
                return (
                    f"Port {self.port} is already in use and no neighbouring "
                    "port is free. Close the process holding it and restart."
                )
            logger.warning(
                "Proxy port %d is busy; this session listens on %d instead",
                self.port,
                replacement,
            )
            self.port = replacement
            settings.PROXY_PORT = replacement

        # The transparent redirect port is a separate listener (WinDivert
        # re-injects there): it cannot move without re-pointing the OS rules.
        if self.mode in ("transparent", "both") and _port_in_use(TRANSPARENT_PORT):
            return (
                f"Port {TRANSPARENT_PORT} is already in use — another Nyx "
                "instance is probably running. Close all other Nyx "
                "windows and restart."
            )
        return None

    def start(self, fastapi_loop: asyncio.AbstractEventLoop) -> tuple[bool, str]:
        self.fastapi_loop = fastapi_loop
        self._stopped.clear()
        self._startup_done.clear()
        # Clear any stale system proxy settings left by a previous Nyx session
        # that crashed or was killed while in transparent mode — this is the #1
        # reason browsers and OpenCode stop working after a bad Nyx shutdown.
        if platform.system().lower() == "windows":
            _clear_windows_system_proxy()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        for _ in range(60):
            # Wait for the proxy thread to COMPLETE its startup phase before
            # judging — reading _start_error / port state earlier races the
            # thread (the classic "WinDivert says not ready though it started"
            # bug). A port-connectivity check alone is not sufficient: another
            # Nyx instance (or a dying old master) can hold the port, making a
            # failed bind look like success.
            if self._startup_done.is_set():
                break
            time.sleep(0.25)
        if self._start_error is not None:
            err = self._start_error
            self._start_error = None
            msg = f"Proxy failed to start: {err}"
            logger.error(msg)
            return False, msg
        if self._startup_done.is_set():
            # Give the new listener a moment to bind (the bind happens inside
            # master.run(), after _startup_done). A mid-run bind failure caught
            # by _BindErrorWatcher surfaces here instead of "ready" with a
            # dead listener.
            for _ in range(5):
                if self._start_error is not None:
                    break
                time.sleep(0.1)
            if self._start_error is not None:
                err, self._start_error = self._start_error, None
                msg = f"Proxy failed to start: {err}"
                logger.error(msg)
                return False, msg
            logger.info("Proxy engine ready on %s:%d", self.host, self.port)
            return True, "Proxy running"
        msg = "Proxy did not become ready within 15s — check backend logs"
        logger.error(msg)
        return False, msg

    def stop(self):
        self._stopped.set()
        if self._master:
            try:
                self._master.shutdown()
            except Exception as e:
                logger.warning("Error shutting down mitmproxy: %s", e)
        if self._thread and self._thread.is_alive():
            for _ in range(30):
                self._thread.join(timeout=1)
                if not self._thread.is_alive():
                    break
            if self._thread and self._thread.is_alive():
                logger.warning("Proxy thread still alive after 30s shutdown — proceeding anyway")
        self._thread = None
        self._master = None
        _stop_windivert()
        # Re-disable IP forwarding on physical interfaces and clear any system
        # proxy left behind by mitmproxy so browsers/apps work normally after
        # Nyx stops MITM interception.
        if platform.system().lower() == "windows":
            _disable_ip_forwarding()
            _clear_windows_system_proxy()

    def tls_failures(self) -> tuple[int, list[dict]]:
        """Rejected client TLS handshakes since the last reset (count, recent hosts)."""
        if self._tls_fail_tracker is None:
            return 0, []
        return self._tls_fail_tracker.snapshot()

    def reset_tls_failures(self) -> None:
        if self._tls_fail_tracker is not None:
            self._tls_fail_tracker.reset()

    def activity_snapshot(self) -> list[dict]:
        """Per-target (IP, host) contacts from SNI + HTTP — works WITHOUT the CA."""
        if self._activity_tracker is None:
            return []
        return self._activity_tracker.snapshot()

    def reset_activity(self) -> None:
        if self._activity_tracker is not None:
            self._activity_tracker.reset()

    def _run(self):
        self._start_error = None
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_mitmproxy())
        except Exception as e:
            logger.error("mitmproxy thread crashed: %s", e, exc_info=True)
            self._start_error = str(e)

    async def _start_mitmproxy(self):
        # Must run BEFORE the options are built: the fallback port is written
        # into both self.port and settings.PROXY_PORT, and the listener (plus
        # the firewall rule and the UI) reads those. Doing it later left the
        # already-built Options pointing at the busy port.
        preflight_error = self._preflight_ports()
        if preflight_error:
            logger.critical(preflight_error)
            self._start_error = preflight_error
            self.transport_ready = False
            self._startup_done.set()
            return
        mitm_mode = ["regular"]
        if self.mode == "transparent" or self.mode == "both":
            if platform.system().lower() == "windows":
                if not _start_windivert(TRANSPARENT_PORT):
                    logger.error(
                        "WinDivert not available — falling back to regular proxy mode. "
                        "Transparent MITM requires admin privileges. "
                        "Run Nyx as Administrator for full functionality."
                    )
                    self.mode = "regular"
                else:
                    mitm_mode = ["regular", f"transparent@{TRANSPARENT_PORT}"]
                    _fix_win_divert_port(TRANSPARENT_PORT)
            else:
                mitm_mode = ["regular", f"transparent@{TRANSPARENT_PORT}"]
        options = Options(
            listen_host=self.host,
            listen_port=self.port,
            mode=mitm_mode,
            ssl_insecure=True,
            ignore_hosts=settings.proxy_ignore_hosts
            + [r"^ws\.telemetry\.(samsungapps|samsung|samsungmobile)\.com$"],
        )
        # Transparent transport is really ready only when a transparent mode
        # made it into the loaded mitmproxy modes (i.e. WinDivert started on
        # Windows — otherwise we fell back to regular and phones won't reach
        # the proxy).
        self.transport_ready = any(m.startswith("transparent") for m in mitm_mode)
        if self.mode in ("transparent", "both") and not self.transport_ready:
            logger.warning(
                "Transparent transport NOT ready — proxy running regular only. "
                "Traffic from target devices will not reach the proxy unless "
                "they use a manual proxy (Stealth Mode)."
            )
        try:
            self._master = DumpMaster(options)
        except OSError as e:
            msg = f"Cannot start proxy on {self.host}:{self.port} — port in use: {e}"
            if "address already in use" in str(e).lower() or "10048" in str(e):
                msg = (
                    f"Port {self.port} is already in use. Another Nyx instance "
                    f"(or the previous one still shutting down) is holding it. "
                    f"Close the other Nyx window and retry."
                )
            logger.critical(msg)
            self._start_error = msg
            self.transport_ready = False
            self._startup_done.set()
            return
        except Exception as e:
            msg = f"Cannot start proxy in transparent mode: {e}"
            logger.critical(msg)
            self._start_error = msg
            self.transport_ready = False
            self._startup_done.set()
            return
        from core.proxy.addons.logger import LoggerAddon
        from core.proxy.addons.stealth import StealthAddon
        from core.proxy.addons.tls_gate import TlsMitmGate

        # Watch for a stolen-port bind failure (see _BindErrorWatcher).
        self._master.addons.add(_BindErrorWatcher(self))

        # TLS MITM is a user-controlled setting (default ON). Unlike a
        # hard gate tied to the local trust store, we always decrypt HTTPS
        # when the operator enables it — the target device must trust the
        # Nyx CA (DeployBox) to avoid cert warnings, exactly like Burp.
        # The local machine's trust store is irrelevant for device MITM.
        self.tls_mitm = bool(settings.TLS_MITM)
        if not self.tls_mitm:
            logger.warning(
                "TLS_MITM=%s — HTTPS will be passed through without decryption "
                "(plain HTTP proxy only). Enable 'Decrypt HTTPS' in the MITM page.",
                settings.TLS_MITM,
            )

        self._master.addons.add(LoggerAddon(self, max_body_size=settings.MAX_BODY_SIZE_BYTES))
        self._master.addons.add(StealthAddon())
        self._master.addons.add(TlsMitmGate(enabled=self.tls_mitm))
        from core.proxy.addons.tls_fail import TlsFailTracker
        self._tls_fail_tracker = TlsFailTracker(self)
        self._master.addons.add(self._tls_fail_tracker)
        from core.proxy.addons.activity import ActivityTracker
        self._activity_tracker = ActivityTracker(self)
        self._master.addons.add(self._activity_tracker)
        for addon in self._addons:
            self._master.addons.add(addon)
        # Startup phase done: sync point for start() / switch_to_transparent().
        self._startup_done.set()
        await self._master.run()
        # Master exited (shutdown or startup bind failure). Explicitly stop the
        # server instances — mitmproxy leaves the asyncio server sockets bound
        # when the master is shut down, so without this the listener port stays
        # occupied and a later engine restart would fail to bind.
        try:
            ps = self._master.addons.get("proxyserver")
            if ps is not None and getattr(ps, "servers", None) is not None:
                await ps.servers.update([])
        except Exception as e:
            logger.debug("Proxyserver teardown error: %s", e)

    def switch_to_transparent(self) -> tuple[bool, str]:
        if self.mode == "transparent":
            return True, "Already in transparent mode"
        if self.mode == "both":
            self.mode = "transparent"
            logger.info("Already running in 'both' mode (includes transparent) — no restart needed")
            return True, "Proxy already in transparent mode (was 'both')"
        logger.info("Switching proxy mode from '%s' to 'transparent'", self.mode)

        if platform.system().lower() == "windows":
            if not _check_win_divert():
                return False, (
                    "WinDivert (required for transparent proxy) is not available. "
                    "Make sure Nyx is running as Administrator. "
                    "If it still fails, configure the target device's proxy manually to NYX_IP:8080."
                )
            if not _enable_ip_forwarding():
                logger.warning(
                    "Could not enable IP forwarding. "
                    "Traffic from other devices may not reach the proxy. "
                    "Run 'netsh interface ipv4 set forwarding enabled' or enable it in adapter settings."
                )

        self.stop()
        self.mode = "transparent"
        if not self.fastapi_loop:
            self.mode = "regular"
            logger.error("Cannot restart proxy: no fastapi loop available")
            return False, "No FastAPI event loop available"
        ok, msg = self.start(self.fastapi_loop)
        if not ok:
            self.mode = "regular"
            logger.error("Proxy failed to start in transparent mode: %s", msg)
            return False, f"Transparent proxy failed: {msg}"
        if self._start_error is not None:
            err, self._start_error = self._start_error, None
            self.mode = "regular"
            logger.error("Transparent proxy startup failed: %s", err)
            return False, f"Transparent proxy failed: {err}"
        if not self.transport_ready:
            self.mode = "regular"
            logger.error("Transparent transport not ready after restart (WinDivert unavailable)")
            return False, (
                "Transparent transport not ready after restart. WinDivert "
                "(required for transparent capture) failed to start. Run Nyx "
                "as Administrator, or use Stealth Mode (manual proxy)."
            )
        logger.info("Proxy restarted in transparent mode on %s:%d", self.host, self.port)
        return True, "Proxy running in transparent mode"

    def emit_event(self, event: dict):
        if not self.fastapi_loop:
            logger.warning("emit_event dropped (no fastapi loop): %s", event.get("type"))
            return
        if self._stopped.is_set():
            logger.warning("emit_event dropped (proxy stopped): %s", event.get("type"))
            return
        try:
            future = asyncio.run_coroutine_threadsafe(
                self.event_bus.publish(event),
                self.fastapi_loop
            )
            def _log_future_exception(f):
                exc = f.exception()
                if exc:
                    logger.error("emit_event handler error: %s", exc)
            future.add_done_callback(_log_future_exception)
        except Exception as e:
            logger.error("emit_event failed: %s", e)
