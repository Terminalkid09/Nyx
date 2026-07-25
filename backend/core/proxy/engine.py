import asyncio
import logging
import platform
import socket
import subprocess
import threading
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
        return ["netsh int ip set forwarding enabled"]
    return ["netsh int ip set forwarding disabled"]


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


def _fix_win_divert_port(proxy_port: int):
    """Monkey-patch TransparentProxy on Windows to use the correct proxy port."""
    if platform.system().lower() != "windows":
        return
    try:
        from mitmproxy.platform.windows import TransparentProxy as TP
        _orig_setup = TP.setup
        from mitmproxy.platform.windows import REDIRECT_API_PORT, REDIRECT_API_HOST
        def _patched_setup():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_unavailable = s.connect_ex((REDIRECT_API_HOST, REDIRECT_API_PORT))
            if server_unavailable:
                proxifier = TP(proxy_port=proxy_port)
                proxifier.start()
        TP.setup = _patched_setup
        logger.info("Monkey-patched TransparentProxy to use proxy port %d", proxy_port)
    except Exception as e:
        logger.warning("Failed to patch WinDivert port: %s", e)


class ProxyEngine:
    def __init__(self, event_bus: EventBus, host="127.0.0.1", port=8080, mode="regular"):
        self.event_bus = event_bus
        self.host = host
        self.port = port
        self.mode = mode
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._master: DumpMaster | None = None
        self.fastapi_loop: asyncio.AbstractEventLoop | None = None
        self.current_session_id = None
        self._stopped = threading.Event()
        self._addons: list = []

    def register_addon(self, addon):
        self._addons.append(addon)

    def start(self, fastapi_loop: asyncio.AbstractEventLoop):
        self.fastapi_loop = fastapi_loop
        self._stopped.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stopped.set()
        if self._master:
            try:
                self._master.shutdown()
            except Exception as e:
                logger.warning("Error shutting down mitmproxy: %s", e)
        if self._thread and self._thread.is_alive():
            for _ in range(10):
                self._thread.join(timeout=1)
                if not self._thread.is_alive():
                    break
        self._thread = None
        self._master = None

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start_mitmproxy())

    async def _start_mitmproxy(self):
        if self.mode == "transparent" or self.mode == "both":
            _fix_win_divert_port(8082)
        mitm_mode = ["regular"]
        if self.mode == "transparent" or self.mode == "both":
            mitm_mode = ["regular", "transparent@8082"]
        options = Options(
            listen_host=self.host,
            listen_port=self.port,
            mode=mitm_mode,
            ssl_insecure=True,
        )
        self._master = DumpMaster(options)
        from core.proxy.addons.logger import LoggerAddon
        self._master.addons.add(LoggerAddon(self, max_body_size=settings.MAX_BODY_SIZE_BYTES))
        for addon in self._addons:
            self._master.addons.add(addon)
        await self._master.run()

    def switch_to_transparent(self) -> bool:
        if self.mode == "transparent":
            return True
        logger.info("Switching proxy mode from '%s' to 'transparent'", self.mode)
        self.stop()
        self.mode = "transparent"
        if self.fastapi_loop:
            try:
                self.start(self.fastapi_loop)
                logger.info("Proxy restarted in transparent mode on %s:%d", self.host, self.port)
                return True
            except Exception as e:
                logger.error("Failed to restart proxy in transparent mode: %s", e)
                self.mode = "regular"
                return False
        logger.error("Cannot restart proxy: no fastapi loop available")
        self.mode = "regular"
        return False

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
