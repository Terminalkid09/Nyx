import hmac
import json
import logging
import os
import secrets
from pathlib import Path

from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

_KEY_DIR = Path(os.environ.get("NYX_HOME") or Path(__file__).resolve().parent.parent.parent)
_KEY_DIR.mkdir(parents=True, exist_ok=True)
KEY_FILE = _KEY_DIR / "nyx.secret"


def _load_or_generate_key() -> str:
    data = {}
    if KEY_FILE.exists():
        try:
            data = json.loads(KEY_FILE.read_text())
            key = data.get("api_key", "")
            if key and len(key) >= 16:
                return key
        except Exception:
            data = {}
    key = secrets.token_urlsafe(32)
    data["api_key"] = key
    try:
        KEY_FILE.write_text(json.dumps(data, indent=2))
        os.chmod(str(KEY_FILE), 0o600)
    except Exception as e:
        logger.warning("Could not save API key to %s: %s", KEY_FILE, e)
    return key


API_KEY = _load_or_generate_key()


async def verify_api_key(request: Request, call_next):
    if request.method == "OPTIONS":
        return await call_next(request)
    path = request.url.path

    # Only protect /api/ paths; everything else (SPA, assets, health, WS) is public
    if not path.startswith("/api/"):
        return await call_next(request)

    # Allow requests from localhost to pass without key
    # (the desktop app always connects to 127.0.0.1:8000)
    client_host = request.client.host if request.client else ""
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
