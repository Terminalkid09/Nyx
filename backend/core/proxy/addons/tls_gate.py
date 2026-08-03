"""TLS MITM gate addon.

Controls whether mitmproxy *decrypts* TLS connections (TLS MITM) or simply
tunnels them untouched (CONNECT passthrough / "plain proxy").

TLS MITM is a user-controlled setting (``settings.TLS_MITM``, toggled from
the MITM page — ``POST /api/mitm/tls``). When enabled, every TLS connection
through the proxy is decrypted with the Nyx CA; the target device must trust
that CA (DeployBox) to browse without certificate warnings — same model as
Burp. When disabled, connections are passed through end-to-end untouched
while plain-HTTP traffic continues to be intercepted.

The addon reads the setting at runtime on every client hello, so toggling
it from the UI takes effect immediately without restarting the proxy.
"""

import logging

from core.config import settings
from mitmproxy.proxy.layers.tls import ClientHelloData

logger = logging.getLogger(__name__)


class TlsMitmGate:
    """Set ``ignore_connection`` on TLS handshakes when TLS MITM is disabled."""

    def __init__(self, enabled: bool = True):
        # `enabled` is kept for tests/back-compat; runtime behaviour follows
        # settings.TLS_MITM so the UI toggle works live.
        self.enabled = enabled

    @property
    def _effective(self) -> bool:
        # `enabled=False` (tests/back-compat) forces passthrough; otherwise the
        # live UI toggle in settings.TLS_MITM decides at runtime.
        if not self.enabled:
            return False
        return bool(settings.TLS_MITM)

    def tls_clienthello(self, data: ClientHelloData) -> None:
        if not self._effective:
            data.ignore_connection = True
            if data.context is not None:
                conn = data.context.client
                logger.debug(
                    "TLS MITM disabled — tunnelling TLS untouched for %s:%s",
                    getattr(conn, "peername", ("?", 0))[0] if getattr(conn, "peername", None) else "?",
                    getattr(conn, "peername", (0, 0))[1] if getattr(conn, "peername", None) else 0,
                )