"""Tracks TLS handshakes the *target* rejects.

When the target does not trust the Nyx CA, every HTTPS connection dies during
the client TLS handshake — before any request data flows — so mitmproxy
records no flow for it. The UI would show "0 flows" while the phone is
constantly failing TLS. This addon records the rejected handshakes (SNI /
server address / error) so the UI can surface exactly what the target tried
to reach and why it failed.
"""
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.proxy.engine import ProxyEngine

logger = logging.getLogger(__name__)

MAX_FAILED_HOSTS = 20


class TlsFailTracker:
    """mitmproxy addon: collects ``tls_failed_client`` events."""

    def __init__(self, engine: "ProxyEngine") -> None:
        self.engine = engine
        self.fail_count = 0
        self.failed_hosts: deque[dict[str, Any]] = deque(maxlen=MAX_FAILED_HOSTS)

    def reset(self) -> None:
        self.fail_count = 0
        self.failed_hosts.clear()

    def tls_failed_client(self, data: Any) -> None:
        """The client (target device) aborted the TLS handshake with Nyx."""
        conn = getattr(data, "conn", None)
        host = getattr(conn, "sni", None)
        server_addr = getattr(conn, "server_address", None)
        if not host and server_addr:
            host = f"{server_addr[0]}:{server_addr[1]}"
        if not host:
            host = "unknown"
        error = getattr(conn, "error", None) or "handshake failed"
        self.fail_count += 1
        self.failed_hosts.appendleft({"host": host, "error": error, "ts": time.time()})
        if self.fail_count <= 3:
            logger.warning("TLS handshake rejected by target: %s (%s)", host, error)

    def snapshot(self) -> tuple[int, list[dict[str, Any]]]:
        return self.fail_count, list(self.failed_hosts)