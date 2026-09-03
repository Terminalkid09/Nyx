import hmac
import logging
import time
import threading
from collections import defaultdict
from urllib.parse import urlparse

from fastapi import Request, WebSocket
from fastapi.responses import JSONResponse

from core.secrets_store import SECRET_FILE as KEY_FILE
from core.secrets_store import api_key as _stored_api_key

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

    # Allow requests from localhost to pass without key
    # (the desktop app always connects to 127.0.0.1:8000)
    if client_host in ("127.0.0.1", "::1", "localhost"):
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
_WS_ALLOWED_PORTS = (8000, 5173)


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
    return port in _WS_ALLOWED_PORTS
