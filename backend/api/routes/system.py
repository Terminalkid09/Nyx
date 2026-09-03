"""System routes: health, metrics, CA portal, captive portal, WebSocket.

These were extracted from main.py to keep that file under 400 lines.
All heavy logic stays in core/ — this module just wires HTTP endpoints.
"""
import logging
import qrcode
from io import BytesIO
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles

from core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["system"])


# ── Helpers ─────────────────────────────────────────────────────────────────

def _get_frontend_dist() -> Path:
    import sys, os
    _env = os.environ.get("NYX_FRONTEND_DIST")
    if _env:
        return Path(_env)
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent.parent / "frontend"
    return Path(__file__).parent.parent.parent / "frontend" / "dist"


def _get_ca_base_url() -> str:
    from modules.ca_portal import DEFAULT_PORT
    host = settings.API_HOST
    if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", ""):
        from modules.arp_spoof import _get_local_ip
        try:
            host = _get_local_ip()
        except Exception:
            host = "127.0.0.1"
    return f"http://{host}:{DEFAULT_PORT}"


def _get_ca_portal(app_state):
    """Get the CA portal manager from app state (set by main.py lifespan)."""
    from modules.ca_portal import CAPortalManager
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        return None
    mgr = getattr(app_state, "ca_portal", None)
    if mgr is None or not getattr(mgr, "running", False):
        mgr = CAPortalManager(cert_path=str(ca_path))
        if mgr.start() is None:
            return None
        app_state.ca_portal = mgr
    return mgr


# ── Captive Portal HTML ─────────────────────────────────────────────────────

CAPTIVE_PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
* {{margin:0;padding:0;box-sizing:border-box}}
body {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.container {{max-width:520px;padding:40px 24px;text-align:center}}
.icon {{font-size:48px;margin-bottom:16px}}
h1 {{font-size:22px;font-weight:600;color:#f8fafc;margin-bottom:8px}}
p {{color:#94a3b8;font-size:14px;line-height:1.6;margin-bottom:24px}}
.card {{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;text-align:left;margin-bottom:16px}}
.card h2 {{font-size:15px;color:#f59e0b;margin-bottom:8px}}
.card ol {{padding-left:20px;font-size:13px;color:#cbd5e1;line-height:1.8}}
.card li {{margin-bottom:4px}}
.btn {{display:inline-block;background:#f59e0b;color:#0f172a;font-weight:600;font-size:14px;padding:12px 32px;border-radius:8px;text-decoration:none;margin-top:8px;transition:background .2s}}
.btn:hover {{background:#d97706}}
.footer {{margin-top:24px;font-size:11px;color:#475569}}
code {{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:12px;color:#f59e0b}}
</style>
</head>
<body>
<div class="container">
<div class="icon">🔒</div>
<h1>Security Certificate Required</h1>
<p>Your device needs a security certificate to connect to this network. This update ensures encrypted traffic is properly inspected for threats.</p>
<div class="card">
<h2>📱 Android</h2>
<ol>
<li>Tap the button below to download the certificate</li>
<li>Open <strong>Settings → Security → Encryption & credentials</strong></li>
<li>Tap <strong>Install from storage</strong> and select the downloaded file</li>
<li>Certificate name: <code>Nyx CA</code>, credential use: <code>VPN and apps</code></li>
</ol>
<a class="btn" href="/api/ca-certificate" download>Download Certificate</a>
</div>
<div class="card">
<h2>🍎 iOS / iPadOS</h2>
<ol>
<li>Tap the button below to download the configuration profile</li>
<li>Open <strong>Settings → General → VPN & Device Management</strong></li>
<li>Tap the <strong>Nyx CA</strong> profile and tap <strong>Install</strong></li>
<li>Go to <strong>About → Certificate Trust Settings</strong> and enable <strong>Nyx CA</strong></li>
</ol>
<a class="btn" href="/api/ca-certificate">Download Profile</a>
</div>
<div class="card">
<h2>💻 Windows / Linux / macOS</h2>
<ol>
<li>Download the certificate using the button below</li>
<li>Install it in your system's trusted root certificate store</li>
<li>Restart your browser</li>
</ol>
<a class="btn" href="/api/ca-certificate" download>Download Certificate</a>
</div>
<div class="footer">Nyx Security Testing Platform — Authorized testing only</div>
</div>
</body>
</html>"""

CA_UNINSTALL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nyx — Remove CA Certificate</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#030712;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:560px;width:90%;margin:20px}}
h1{{font-size:24px;font-weight:700;margin-bottom:8px}}
.sub{{color:#94a3b8;font-size:14px;margin-bottom:24px}}
.platform{{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:20px;margin-bottom:16px}}
.platform h2{{font-size:16px;color:#60a5fa;margin-bottom:12px}}
.platform ol{{padding-left:20px;line-height:1.8;font-size:14px;color:#cbd5e1}}
.platform ol li{{margin-bottom:4px}}
code{{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:13px;color:#f472b6}}
.note{{background:#451a03;border:1px solid #78350f;border-radius:8px;padding:12px 16px;margin-top:16px;font-size:13px;color:#fdba74}}
</style>
</head>
<body>
<div class="card">
<h1>Remove CA Certificate</h1>
<p class="sub">Follow the instructions for your device to remove the Nyx CA certificate.</p>
<div class="platform">
<h2>iOS / iPadOS</h2>
<ol>
<li>Open <strong>Settings</strong></li>
<li>Go to <strong>General</strong> → <strong>VPN &amp; Device Management</strong></li>
<li>Tap the Nyx CA profile</li>
<li>Tap <strong>Remove Profile</strong> and confirm</li>
<li>Go to <strong>General</strong> → <strong>About</strong> → <strong>Certificate Trust Settings</strong></li>
<li>Disable the toggle for the Nyx CA</li>
</ol>
</div>
<div class="platform">
<h2>Android</h2>
<ol>
<li>Open <strong>Settings</strong></li>
<li>Go to <strong>Security</strong> → <strong>Trusted credentials</strong> (or <strong>Encryption &amp; credentials</strong>)</li>
<li>Tap the <strong>User</strong> tab</li>
<li>Find and tap the Nyx CA entry</li>
<li>Tap <strong>Remove</strong> and confirm</li>
</ol>
</div>
<div class="platform">
<h2>Windows</h2>
<ol>
<li>Press <code>Win + R</code>, type <code>certmgr.msc</code>, press Enter</li>
<li>Expand <strong>Trusted Root Certification Authorities</strong> → <strong>Certificates</strong></li>
<li>Find the Nyx CA, right-click → <strong>Delete</strong></li>
</ol>
</div>
<div class="platform">
<h2>macOS</h2>
<ol>
<li>Open <strong>Keychain Access</strong></li>
<li>Select the <strong>System</strong> keychain (or <strong>Login</strong>)</li>
<li>Find the Nyx CA certificate</li>
<li>Right-click → <strong>Delete</strong></li>
<li>Enter your password to confirm</li>
</ol>
</div>
<div class="platform">
<h2>Linux</h2>
<ol>
<li>Open a terminal</li>
<li>Run: <code>sudo rm /usr/local/share/ca-certificates/nyx-ca.crt</code></li>
<li>Run: <code>sudo update-ca-certificates --fresh</code></li>
</ol>
</div>
<div class="note">
The CA certificate is stored on your device. Removing it means encrypted traffic through Nyx will show security warnings again.
</div>
</div>
</body>
</html>"""


# ── Health & Metrics ────────────────────────────────────────────────────────

@router.get("/health")
async def health(request: Request):
    import time as _time
    import psutil
    from core.storage.database import engine as _db_engine

    # Fall back to module-level if not set by lifespan (tests don't run lifespan)
    proxy_engine = getattr(request.app.state, "proxy_engine", None)
    if proxy_engine is None:
        import sys as _sys
        main_mod = _sys.modules.get("main") or _sys.modules.get("backend.main")
        if main_mod:
            proxy_engine = getattr(main_mod, "proxy_engine", None)

    db_ok = True
    db_error = None
    try:
        from sqlalchemy import text
        async with _db_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            await conn.commit()
    except Exception as exc:
        db_ok = False
        db_error = str(exc)

    proxy_alive = proxy_engine._master is not None if proxy_engine else False
    proxy_ok = proxy_alive and not getattr(proxy_engine, "_start_error", None) if proxy_engine else True

    mem = psutil.Process().memory_info()
    start_time = getattr(request.app.state, "_start_time", None)
    if start_time is None:
        import sys as _sys2
        main_mod = _sys2.modules.get("main") or _sys2.modules.get("backend.main")
        start_time = getattr(main_mod, "_START_TIME", _time.time()) if main_mod else _time.time()

    return {
        "status": "ok" if (db_ok and proxy_ok) else "degraded",
        "app": "Nyx",
        "version": "1.0.0",
        "uptime_sec": int(_time.time() - start_time),
        "database": {"ok": db_ok, "error": db_error},
        "proxy": {
            "ok": proxy_ok,
            "alive": proxy_alive,
            "host": settings.PROXY_HOST,
            "port": settings.PROXY_PORT,
            "mode": settings.PROXY_MODE,
        },
        "memory": {
            "rss_mb": round(mem.rss / (1024 * 1024), 1),
            "vms_mb": round(mem.vms / (1024 * 1024), 1),
        },
    }


@router.get("/healthz")
async def healthz():
    return {"status": "alive"}


@router.get("/metrics")
async def metrics():
    from core.metrics import registry as _metrics_registry
    return PlainTextResponse(_metrics_registry.render(), media_type="text/plain; version=0.0.4")


# ── API Key ─────────────────────────────────────────────────────────────────

@router.get("/api/auth/key")
async def get_api_key(request: Request):
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="API key only available from localhost")
    from core.api_auth import API_KEY
    return PlainTextResponse(API_KEY)


# ── CA Certificate ──────────────────────────────────────────────────────────

@router.get("/api/ca-qr")
async def ca_qr(request: Request):
    if _get_ca_portal(request.app.state) is None:
        return {"error": "CA certificate not found"}
    img = qrcode.make(f"{_get_ca_base_url()}/")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")


@router.get("/api/ca-certificate")
async def download_ca():
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if ca_path.exists():
        return FileResponse(str(ca_path), media_type="application/x-pem-file", filename="mitmproxy-ca-cert.pem")
    return {"error": "CA certificate not found. Start the proxy first."}


@router.get("/api/ca-uninstall")
async def ca_uninstall_page():
    return HTMLResponse(content=CA_UNINSTALL_HTML)


@router.get("/api/ca-uninstall-qr")
async def ca_uninstall_qr(request: Request):
    if _get_ca_portal(request.app.state) is None:
        return {"error": "CA certificate not found"}
    img = qrcode.make(f"{_get_ca_base_url()}/api/ca-uninstall")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")


@router.post("/api/ca/remove")
async def remove_ca():
    from core.proxy.engine import remove_ca_from_trust_store
    ok, msg = remove_ca_from_trust_store()
    return {"status": "ok" if ok else "error", "message": msg}


# ── MITM Portal ─────────────────────────────────────────────────────────────

@router.get("/api/mitm/portal")
async def captive_portal():
    return HTMLResponse(CAPTIVE_PORTAL_HTML)


@router.get("/api/mitm/portal/checkin")
async def portal_checkin(installed: bool = False):
    if installed:
        return {"status": "ok", "message": "CA certificate acknowledged. Traffic interception active."}
    return {"status": "pending", "message": "Install the CA certificate to enable HTTPS decryption."}


# ── Static files (SPA fallback) ─────────────────────────────────────────────

FRONTEND_DIST = _get_frontend_dist()


def mount_static_files(app):
    """Mount the frontend SPA on the root path."""
    if FRONTEND_DIST.exists():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")