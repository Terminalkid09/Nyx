"""Live per-target activity monitor — visibility WITHOUT decryption.

Every TLS ClientHello carries the requested hostname in the clear (SNI), and
plain-HTTP requests carry the Host header. This addon records both per target
IP, so the UI can show *what each intercepted device is doing right now*
(domains contacted, request counts, recency) even when the Nyx CA is NOT
installed on the device and nothing can be decrypted.

This reframes "TLS handshake failed" telemetry into what it actually is:
metadata-level network visibility — the legitimate value of a transparent
MITM against devices you cannot install a certificate on.
"""
import logging
import time
from collections import deque
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.proxy.engine import ProxyEngine

logger = logging.getLogger(__name__)

MAX_ENTRIES = 500


class ActivityTracker:
    """mitmproxy addon: records (target IP -> hostname) contacts from SNI and HTTP."""

    def __init__(self, engine: "ProxyEngine") -> None:
        self.engine = engine
        # key (ip, host) -> {"count": int, "last": float}
        self._entries: dict[tuple[str, str], dict[str, Any]] = {}
        # insertion order for FIFO eviction of the oldest pairs
        self._order: deque[tuple[str, str]] = deque()

    def reset(self) -> None:
        self._entries.clear()
        self._order.clear()

    def _record(self, ip: str | None, host: str | None) -> None:
        if not ip or not host:
            return
        host = host.strip().rstrip(".")
        if not host:
            return
        now = time.time()
        key = (ip, host)
        entry = self._entries.get(key)
        if entry is not None:
            entry["count"] += 1
            entry["last"] = now
            return
        self._entries[key] = {"count": 1, "last": now}
        self._order.append(key)
        while len(self._order) > MAX_ENTRIES:
            oldest = self._order.popleft()
            self._entries.pop(oldest, None)

    def tls_clienthello(self, data: Any) -> None:
        """Fires on EVERY TLS connection attempt — CA trusted or not."""
        ctx = getattr(data, "context", None)
        client = getattr(ctx, "client", None)
        peername = getattr(client, "peername", None)
        ip = peername[0] if peername else None
        client_hello = getattr(data, "client_hello", None)
        sni = getattr(client_hello, "sni", None)
        self._record(ip, sni)

    def request(self, flow: Any) -> None:
        """Plain-HTTP requests (and decrypted HTTPS when the CA IS trusted).

        Records every flow regardless of ``capture_active``: during transparent
        MITM the browser's capture toggle is OFF but target-device traffic still
        flows through the proxy and SHOULD be visible in the activity monitor.
        """
        try:
            ip = flow.client_conn.peername[0]
            host = flow.request.pretty_host
        except Exception:
            return
        self._record(ip, host)

    def snapshot(self) -> list[dict[str, Any]]:
        """Most recent first: [{ip, host, count, last_seen ISO-8601}]."""
        items = sorted(self._entries.items(), key=lambda kv: kv[1]["last"], reverse=True)
        from datetime import datetime, timezone

        return [
            {
                "ip": ip,
                "host": host,
                "count": entry["count"],
                "last_seen": datetime.fromtimestamp(entry["last"], tz=timezone.utc).isoformat(),
                "ts": entry["last"],
            }
            for (ip, host), entry in items
        ]
