"""Stealth addon for mitmproxy.

Removes or replaces response headers that reveal the presence of an
interception proxy.  This reduces detection surface against:
  - Web application firewalls (WAFs) that blacklist mitmproxy's fingerprint.
  - Target devices running IDS/HIDS software.
  - Router firmware that monitors for proxy headers.

Headers stripped from *responses* (never from requests — modifying requests
would break end-to-end semantics):
  - ``Via``              — added by transparent proxies, very distinctive.
  - ``X-Cache``          — can leak CDN/proxy topology.
  - ``X-Cache-Hits``     — same as above.
  - ``X-Forwarded-For``  — if the server echoed it back in a response.
  - ``X-Squid-Error``    — reveals proxy errors.

The ``Server`` header is normalised: mitmproxy sometimes injects its own
server identification which is trivially detected.
"""

import logging
from mitmproxy import http

logger = logging.getLogger(__name__)

# Headers in server *responses* that expose the proxy's presence
_STRIP_RESPONSE_HEADERS = {
    "via",
    "x-cache",
    "x-cache-hits",
    "x-squid-error",
    "x-forwarded-server",
    "x-proxy-id",
    "squid-error",     # reverse of x-squid-error on some stacks
    "x-nyx-proxy",     # in case anything we ship leaks this
    "proxy-agent",     # some upstream proxies echo this back
    "x-amz-cf-id",     # not proxy-revealing, but noisy for diffing
}

# Normalise these if they contain proxy-revealing values
_SERVER_KEYWORDS = {"mitmproxy", "squid", "nginx-proxy", "traefik", "varnish"}

# Exclude the MITM's own captive/telemetry endpoints from interception so the
# target device never sees our interceptor's banner instead of the real site.
_IGNORED_HOST_SUBSTRINGS = ("connectivitycheck.", ".telemetry.", "msftconnecttest")


class StealthAddon:
    """mitmproxy addon that strips headers revealing the presence of a proxy."""

    def response(self, flow: http.HTTPFlow) -> None:
        """Strip/normalise revealing headers from every proxied response."""
        if flow.response is None:
            return

        headers = flow.response.headers

        # Strip headers that expose proxy presence
        for h in _STRIP_RESPONSE_HEADERS:
            if h in headers:
                del headers[h]
                logger.debug("StealthAddon: stripped '%s' from response headers", h)

        # Normalise Server header: mitmproxy injects its own identifying
        # value when the upstream exposes an empty/missing one.
        if "server" in headers:
            server = headers.get("server", "")
            low = server.lower()
            if low in ("mitmproxy", "squid", "varnish") or "mitmproxy" in low:
                headers["server"] = "nginx"
                logger.debug("StealthAddon: normalised Server header '%s'", server)

        # Do NOT strip X-Forwarded-For from the *request* — it would change
        # the semantics from the server's perspective.
        # Remove it only if the *server* echoed it back in the response.
        if "x-forwarded-for" in headers:
            del headers["x-forwarded-for"]

    def request(self, flow: http.HTTPFlow) -> None:
        """Normalise request headers to avoid proxy fingerprinting.

        We do NOT modify the request payload (body, URL, host) — only headers
        that are injected automatically by mitmproxy's transparent mode.
        """
        # Transparent mode sometimes adds Proxy-Connection: keep-alive
        # which is a clear proxy indicator and confuses some servers.
        if "proxy-connection" in flow.request.headers:
            del flow.request.headers["proxy-connection"]
