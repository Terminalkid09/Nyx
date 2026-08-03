"""TLS MITM gate addon.

Controls whether mitmproxy *decrypts* TLS connections (TLS MITM) or simply
tunnels them untouched (CONNECT passthrough / "plain proxy").

When the Nyx CA is not installed in the local OS trust store, forcing TLS
MITM produces certificate alerts on every HTTPS page of the target device —
which makes the interception look broken ("MITM non mostra niente"). In that
case this addon marks the client hello as ignored so the connection is passed
through end-to-end without decryption, while plain-HTTP traffic continues to
be intercepted.

The decision is made once at engine start (``enabled: bool``) so behaviour is
deterministic and testable.
"""

import logging

from mitmproxy.proxy.layers.tls import ClientHelloData

logger = logging.getLogger(__name__)


class TlsMitmGate:
    """Set ``ignore_connection`` on TLS handshakes when TLS MITM is disabled."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def tls_clienthello(self, data: ClientHelloData) -> None:
        if not self.enabled:
            data.ignore_connection = True
            if data.context is not None:
                conn = data.context.client
                logger.debug(
                    "TLS MITM disabled — tunnelling TLS untouched for %s:%s",
                    getattr(conn, "peername", ("?", 0))[0] if getattr(conn, "peername", None) else "?",
                    getattr(conn, "peername", (0, 0))[1] if getattr(conn, "peername", None) else 0,
                )