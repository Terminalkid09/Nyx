import hmac
import ipaddress
import logging
import secrets
import time
import threading
from collections import defaultdict
from urllib.parse import urlparse

from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse

from core.config import settings
from core.secrets_store import SECRET_FILE as KEY_FILE
from core.secrets_store import api_key as _stored_api_key
from core.secrets_store import restrict_to_owner

logger = logging.getLogger(__name__)


# ── Rate Limiting (token bucket per client IP) ──────────────────────────────
# Protects the local API from accidental or malicious DoS (buggy frontend loop,
# malware on the same machine). In a localhost-only desktop app the risk is low
# but non-zero: a runaway React effect can hammer /api/proxy/requests at 1 kHz
# and starve the proxy engine. 100 req/s with bursts of 50 is generous enough
# for the UI polling loop (~10 req/s) while blocking abuse.
_RATE_LIMIT_RPS = 100.0           # sustained requests per second per IP
_RATE_LIMIT_BURST = 50            # instantaneous burst allowance
_RATE_LIMIT_BUCKETS: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_refill)
_RATE_LIMIT_LOCK = threading.Lock()


def _check_rate_limit(ip: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        tokens, last = _RATE_LIMIT_BUCKETS.get(ip, (_RATE_LIMIT_BURST, now))
        elapsed = now - last
        tokens = min(_RATE_LIMIT_BURST, tokens + elapsed * _RATE_LIMIT_RPS)
        if tokens < 1.0:
            return False
        _RATE_LIMIT_BUCKETS[ip] = (tokens - 1.0, now)
        # Periodic cleanup of stale entries (every 10 min)
        if len(_RATE_LIMIT_BUCKETS) > 1000:
            stale = [k for k, (_, t) in _RATE_LIMIT_BUCKETS.items() if now - t > 600]
            for k in stale:
                del _RATE_LIMIT_BUCKETS[k]
        return True


def _load_or_generate_key() -> str:
    return _stored_api_key()


API_KEY = _load_or_generate_key()


# ── Per-boot session token (SEC-03b) ────────────────────────────────────────
# The loopback trust model assumes 127.0.0.1 means "our UI". It does not: every
# process running as the same user can reach the API and read captured traffic.
# A token generated at boot and written next to nyx.secret is only reachable by
# processes that can read NYX_HOME, and it dies with the process, so it cannot
# be baked into an attacker's script. The Electron main process reads the file
# and passes the value to the renderer through the preload bridge.
SESSION_TOKEN_FILE = KEY_FILE.parent / "session.token"


def _new_session_token() -> str:
    token = secrets.token_urlsafe(32)
    try:
        SESSION_TOKEN_FILE.write_text(token, encoding="utf-8")
        restrict_to_owner(SESSION_TOKEN_FILE)
    except Exception as e:
        logger.warning("Could not persist the session token to %s: %s", SESSION_TOKEN_FILE, e)
    return token


SESSION_TOKEN = _new_session_token()

# Endpoints a plain browser must reach without the token: the CA download and
# removal pages, and the MITM portal a target device is sent to. They are also
# exempt from the API key for the same reason.
_TOKEN_EXEMPT_PATHS = {
    "/api/auth/key",
    "/api/ca-certificate", "/api/ca-qr",
    "/api/ca-uninstall", "/api/ca-uninstall-qr",
}


# Starlette's TestClient/ASGITransport default hostnames. They are not
# resolvable on the network, so allowing them does not widen the attack surface
# (a DNS-rebinding request carries the attacker's own Host value).
_TEST_HOSTS = {"test", "testserver"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _hostname(host_header: str) -> str:
    """Extract the hostname from a Host header, handling ports and IPv6."""
    host = (host_header or "").strip().lower()
    if not host:
        return ""
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end != -1 else ""
    if host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def is_allowed_host(host_header: str) -> bool:
    """Validate the Host header against the configured allowlist.

    This is the DNS-rebinding guard: a page that makes the browser resolve
    attacker.example to 127.0.0.1 still sends ``Host: attacker.example``, so
    rejecting unknown hosts blocks it even though the TCP peer is loopback.
    """
    allowed = set(_LOOPBACK_HOSTS) | _TEST_HOSTS
    allowed |= {
        h.strip().lower()
        for h in (settings.API_ALLOWED_HOSTS or "").split(",")
        if h.strip()
    }
    return _hostname(host_header) in allowed


def is_trusted_proxy(client_host: str) -> bool:
    """Return True when the peer is inside a configured proxy network."""
    networks = [
        c.strip() for c in (settings.TRUSTED_PROXY_CIDRS or "").split(",")
        if c.strip()
    ]
    if not networks or not client_host:
        return False
    try:
        addr = ipaddress.ip_address(client_host)
    except ValueError:
        return False
    for cidr in networks:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXY_CIDRS entry: %r", cidr)
    return False


async def verify_api_key(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    path = request.url.path

    # Only protect /api/ paths; everything else (SPA, assets, health, WS) is public
    if not path.startswith("/api/"):
        return await call_next(request)

    # Rate limit ALL /api/ requests (including localhost)
    client_host = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_host):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Slow down."})

    # Reject foreign Host headers and browser cross-site calls before the
    # loopback trust shortcut: a DNS-rebound request is also loopback.
    if not is_allowed_host(request.headers.get("host", "")):
        return JSONResponse(
            status_code=403, content={"detail": "Invalid Host header"}
        )
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return JSONResponse(
            status_code=403,
            content={"detail": "Cross-site requests are not allowed"},
        )

    # Allow requests from localhost / a trusted reverse proxy to pass without
    # key (the desktop app always connects to 127.0.0.1:8000).
    if client_host in _LOOPBACK_HOSTS or is_trusted_proxy(client_host):
        # SEC-03b: in the packaged app even loopback callers must prove they
        # were handed the token generated at boot.
        if settings.API_REQUIRE_SESSION_TOKEN:
            exempt = path in _TOKEN_EXEMPT_PATHS or path.startswith("/api/mitm/portal")
            if not exempt:
                given_token = request.headers.get("x-nyx-token", "")
                if not given_token or not hmac.compare_digest(given_token, SESSION_TOKEN):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Missing or invalid X-Nyx-Token"},
                    )
        return await call_next(request)

    # Certain API paths need no key
    safe_paths = {
        "/api/auth/key",
        "/api/ca-certificate", "/api/ca-qr",
        "/api/ca-uninstall", "/api/ca-uninstall-qr",
        "/api/mitm/portal", "/api/mitm/portal/checkin",
    }
    if path in safe_paths or path.startswith("/api/mitm/portal"):
        return await call_next(request)

    given = request.headers.get("x-api-key", "")
    if not given:
        return JSONResponse(status_code=401, content={"detail": "Missing X-API-Key header"})
    if not hmac.compare_digest(given, API_KEY):
        return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
    return await call_next(request)


# Origins allowed to open a WebSocket to the local API: the UI served by this
# backend itself, plus the Vite dev server used during frontend development.
_WS_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")
# 80 is the Docker compose frontend: nginx proxies /ws to the backend. 5173 is
# the Vite dev server. The port the socket was actually opened on is always
# allowed too, because the desktop shell may bind the API to a fallback port
# when 8000 is taken. The Origin must still resolve to a loopback hostname, so
# this does not let a remote site open the socket.
_WS_ALLOWED_PORTS = (80, 8000, 5173)


def validate_ws_origin(ws: WebSocket) -> bool:
    """Reject browser-initiated WebSockets from foreign origins.

    Any web page open in a browser on this machine can script a WebSocket
    connection to ``ws://127.0.0.1:<port>/ws/traffic`` and stream every
    intercepted request/response (credentials included). Browsers always send
    an ``Origin`` header on cross-site WebSocket upgrades, so checking it
    closes that exfiltration vector. Non-browser clients (curl, scripts, the
    Electron main process) send no Origin and are still allowed — consistent
    with the localhost trust model of the REST API.
    """
    origin = ws.headers.get("origin", "")
    if not origin:
        return True
    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.hostname not in _WS_ALLOWED_HOSTS:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port in _WS_ALLOWED_PORTS:
        return True

    # Same-origin check for non-default API ports: the page was served by this
    # very listener, so its origin port is the port the upgrade arrived on.
    try:
        target_port = ws.url.port or (443 if ws.url.scheme == "wss" else 80)
    except Exception:  # noqa: BLE001 — scope may be incomplete in tests
        return False
    return port == target_port
