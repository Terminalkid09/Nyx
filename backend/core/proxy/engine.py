import asyncio
import logging
import platform
import socket
import subprocess
import threading
import time
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from core.events.bus import EventBus
from core.config import settings

logger = logging.getLogger(__name__)


def _setup_linux(proxy_port: int, enable: bool) -> list[str]:
    if enable:
        return [
            f"iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port {proxy_port}",
            f"iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port {proxy_port}",
            "sysctl -w net.ipv4.ip_forward=1",
        ]
    return [
        f"iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port {proxy_port}",
        f"iptables -t nat -D PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port {proxy_port}",
        "sysctl -w net.ipv4.ip_forward=0",
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
        ]
    return [
            "pfctl -F all -f /etc/pf.conf",
            "sysctl -w net.inet.ip.forwarding=0",
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


def _enable_ip_forwarding() -> bool:
    """Enable IP forwarding on Windows so forwarded packets reach WinDivert.
    
    Uses PowerShell (takes effect immediately). Falls back to registry if PS fails.
    """
    if platform.system().lower() != "windows":
        return False
    
    # Method 1: PowerShell — immediate effect, no reboot needed
    try:
        result = subprocess.run(
            ["powershell", "-Command", "Get-NetIPInterface | Set-NetIPInterface -Forwarding Enabled"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            logger.info("IP forwarding enabled via PowerShell")
            return True
        logger.warning("PowerShell IP forwarding failed (rc=%d): %s", result.returncode, result.stderr.strip()[:200])
    except FileNotFoundError:
        logger.warning("PowerShell not found")
    except Exception as e:
        logger.warning("PowerShell IP forwarding failed: %s", e)
    
    # Method 2: registry fallback (requires reboot)
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
        )
        current, _ = winreg.QueryValueEx(key, "IPEnableRouter")
        if current == 1:
            logger.info("IP forwarding already enabled (registry IPEnableRouter=1)")
            winreg.CloseKey(key)
            return True
        winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        logger.warning("IP forwarding enabled via registry — requires reboot to take effect")
        return True
    except PermissionError:
        logger.warning("Cannot enable IP forwarding via registry: requires admin privileges")
    except FileNotFoundError:
        logger.warning("Cannot enable IP forwarding: registry key not found")
    except Exception as e:
        logger.warning("Failed to enable IP forwarding via registry: %s", e)
    return False


_windivert_proxifier: "TransparentProxy | None" = None
_WINDIVERT_PROXY_PORT: int = 0


def _stop_windivert():
    """Stop WinDivert if it was started."""
    global _windivert_proxifier, _WINDIVERT_PROXY_PORT
    if _windivert_proxifier is not None:
        try:
            _windivert_proxifier.shutdown()
            logger.info("WinDivert stopped")
        except Exception as e:
            logger.warning("WinDivert shutdown error: %s", e)
        _windivert_proxifier = None
        _WINDIVERT_PROXY_PORT = 0


def _start_windivert(proxy_port: int) -> bool:
    """Start WinDivert manually to redirect forwarded traffic to the proxy."""
    global _windivert_proxifier, _WINDIVERT_PROXY_PORT
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

        if already_running:
            logger.info("WinDivert API already running on port 8085 — skipping setup")
            return True

        proxifier = TP(proxy_port=proxy_port)
        proxifier.start()
        _windivert_proxifier = proxifier
        _WINDIVERT_PROXY_PORT = proxy_port
        logger.info("WinDivert started with proxy_port=%d, API on port 8085", proxy_port)
        return True
    except PermissionError:
        logger.warning("WinDivert requires admin privileges")
        return False
    except Exception as e:
        logger.warning("WinDivert start failed: %s", e)
        return False


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
        self.fastapi_loop: asyncio.AbstractEventLoop | None = None
        self.current_session_id = None
        self._stopped = threading.Event()
        self._addons: list = []
        self._start_error: str | None = None

    def register_addon(self, addon):
        self._addons.append(addon)

    def start(self, fastapi_loop: asyncio.AbstractEventLoop) -> tuple[bool, str]:
        self.fastapi_loop = fastapi_loop
        self._stopped.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        for _ in range(60):
            if self._start_error is not None:
                err = self._start_error
                self._start_error = None
                msg = f"Proxy failed to start: {err}"
                logger.error(msg)
                return False, msg
            if self._check_port_bound():
                logger.info("Proxy engine ready on %s:%d", self.host, self.port)
                return True, "Proxy running"
            time.sleep(0.25)
        if self._start_error is not None:
            err = self._start_error
            self._start_error = None
            return False, f"Proxy failed to start: {err}"
        msg = "Proxy did not become ready within 15s — check backend logs"
        logger.error(msg)
        return False, msg

    def _check_port_bound(self) -> bool:
        for addr in (self.host, "127.0.0.1"):
            if addr == "0.0.0.0":
                addr = "127.0.0.1"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = s.connect_ex((addr, self.port))
                s.close()
                if result == 0:
                    return True
            except Exception:
                pass
        return False

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
        TRANSPARENT_PORT = 8082
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
        try:
            self._master = DumpMaster(options)
        except OSError as e:
            msg = f"Cannot start proxy on {self.host}:{self.port} — port in use: {e}"
            logger.critical(msg)
            self._start_error = msg
            return
        except Exception as e:
            msg = f"Cannot start proxy in transparent mode: {e}"
            logger.critical(msg)
            self._start_error = msg
            return
        from core.proxy.addons.logger import LoggerAddon
        from core.proxy.addons.stealth import StealthAddon
        self._master.addons.add(LoggerAddon(self, max_body_size=settings.MAX_BODY_SIZE_BYTES))
        self._master.addons.add(StealthAddon())
        for addon in self._addons:
            self._master.addons.add(addon)
        await self._master.run()

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
