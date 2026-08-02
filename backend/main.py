import asyncio
import logging
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from core.config import settings
from core.events.bus import EventBus
from core.proxy.engine import ProxyEngine
from core.storage.database import init_db
from core.storage.traffic import TrafficStorageService, ensure_default_session, DEFAULT_SESSION_ID
from api.websocket.manager import WebSocketManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

event_bus = EventBus()
proxy_engine = ProxyEngine(event_bus, host=settings.PROXY_HOST, port=settings.PROXY_PORT, mode=settings.PROXY_MODE)
ws_manager: WebSocketManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ws_manager
    logger.info("Initializing database...")
    try:
        await init_db()
        await ensure_default_session()
    except Exception as e:
        logger.critical("Database initialization failed: %s", e)
        raise
    TrafficStorageService(event_bus, settings.MAX_BODY_SIZE_BYTES)

    ws_manager = WebSocketManager(event_bus)
    app.state.ws_manager = ws_manager
    app.state.event_bus = event_bus
    app.state.proxy_engine = proxy_engine

    from modules.interceptor.engine import InterceptorEngine
    from modules.session_handling.engine import SessionHandlingEngine
    from modules.automation.engine import AutoScanEngine
    from modules.live_audit.service import LiveAuditService
    from modules.pipeline.orchestrator import ScanPipeline
    from modules.scanner.passive.scanner import PassiveScanner
    from modules.scanner.active.scanner import ActiveScanner
    from modules.match_replace.engine import MatchReplaceEngine
    from modules.proxy_config.service import ProxyConfigService
    from modules.api_inspector.service import ApiInspector
    from core.proxy_utils import set_proxy_config_service

    interceptor_engine = InterceptorEngine(event_bus, proxy_engine)
    session_handling_engine = SessionHandlingEngine(event_bus)
    match_replace_engine = MatchReplaceEngine(event_bus)

    proxy_config_service = ProxyConfigService(event_bus)
    await proxy_config_service.get_active()
    set_proxy_config_service(proxy_config_service)
    app.state.proxy_config_service = proxy_config_service

    passive_scanner = PassiveScanner(event_bus)
    passive_scanner.register()
    active_scanner = ActiveScanner(event_bus)
    app.state.active_scanner = active_scanner
    from api.routes.auth_scan import init_auth_scanner

    api_inspector = ApiInspector(event_bus)
    api_inspector.register()
    app.state.api_inspector = api_inspector
    init_auth_scanner(active_scanner)

    # ── Auto-Auth Keeper (zero-config session recovery) ──────────────────
    from modules.scanner.auth_keeper import AuthKeeper
    auth_keeper = AuthKeeper(event_bus)
    app.state.auth_keeper = auth_keeper
    logger.info("Auth Keeper initialized — will auto-detect login flows and refresh sessions on 401")

    auto_scan_engine = AutoScanEngine(event_bus, passive_scanner, active_scanner)
    app.state.auto_scan_engine = auto_scan_engine
    await auto_scan_engine.start()

    live_audit_service = LiveAuditService(event_bus, auto_scan_engine)
    app.state.live_audit_service = live_audit_service

    app.state.interceptor_engine = interceptor_engine
    app.state.session_handling_engine = session_handling_engine

    proxy_engine.register_addon(interceptor_engine)
    proxy_engine.register_addon(match_replace_engine)
    app.state.match_replace_engine = match_replace_engine

    pipeline_service = ScanPipeline(event_bus)
    app.state.pipeline_service = pipeline_service

    loop = asyncio.get_event_loop()
    proxy_engine.current_session_id = str(DEFAULT_SESSION_ID)
    ok, msg = proxy_engine.start(fastapi_loop=loop)
    if not ok:
        logger.critical("Proxy engine failed to start: %s", msg)
        raise RuntimeError(f"Proxy engine failed to start: {msg}")

    try:
        await session_handling_engine.start()
    except Exception as e:
        logger.error("Session handling engine start failed: %s", e)
    try:
        await interceptor_engine.refresh_rules_cache()
    except Exception as e:
        logger.error("Interceptor rules refresh failed: %s", e)
    try:
        await match_replace_engine.refresh_rules()
        match_replace_engine.start_refresh_task()
    except Exception as e:
        logger.error("Match/replace rules refresh failed: %s", e)

    from modules.automations.scheduled_scans import ScheduledScanService
    from modules.automations.webhooks import WebhookService

    recommender_engine = RecommendationEngine(event_bus)
    app.state.recommender_engine = recommender_engine
    init_recommender(recommender_engine)

    scheduled_scan_service = ScheduledScanService(event_bus)
    scheduled_scan_service.start()
    app.state.scheduled_scan_service = scheduled_scan_service

    webhook_service = WebhookService(event_bus)
    await webhook_service.subscribe_to_events()
    app.state.webhook_service = webhook_service

    try:
        await repeater_service.startup()
    except Exception as e:
        logger.error("Repeater service startup failed: %s", e)

    logger.info("Proxy engine started on %s:%d", settings.PROXY_HOST, settings.PROXY_PORT)

    yield

    logger.info("Shutting down...")
    auto_scan_engine.stop()
    scheduled_scan_service.stop()
    await session_handling_engine.stop()
    await match_replace_engine.stop_refresh_task()
    interceptor_engine.clear_paused_flows()
    # Release MITM resources (firewall rules + any live spoofers/redirects)
    # only now — they must persist for manual-proxy (Stealth) devices for the
    # whole backend lifetime, not just until "Stop" is pressed.
    from api.routes.mitm import shutdown_mitm
    await shutdown_mitm()
    proxy_engine.stop()
    logger.info("Shutdown complete.")


app = FastAPI(lifespan=lifespan)

from core.api_auth import verify_api_key
app.middleware("http")(verify_api_key)

from fastapi.responses import HTMLResponse, PlainTextResponse, Response

@app.get("/api/auth/key")
async def get_api_key(request: Request):
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="API key only available from localhost")
    from core.api_auth import API_KEY
    return PlainTextResponse(API_KEY)


import qrcode
from io import BytesIO
from modules.ca_portal import CAPortalManager, DEFAULT_PORT

_ca_portal: "CAPortalManager | None" = None


def _ca_base_url() -> str:
    """Base URL for the on-demand CA portal, reachable from other devices.

    The main API binds to 127.0.0.1, so the QR codes point at the dedicated
    CA portal server (bound to 0.0.0.0) instead of the API.
    """
    host = settings.API_HOST
    if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0", ""):
        from modules.arp_spoof import _get_local_ip
        try:
            host = _get_local_ip()
        except Exception:
            host = "127.0.0.1"
    return f"http://{host}:{DEFAULT_PORT}"


def _ensure_ca_portal() -> CAPortalManager | None:
    """Start the CA portal server on demand (lazily, never at boot)."""
    global _ca_portal
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        return None
    if _ca_portal is None or not _ca_portal.running:
        mgr = CAPortalManager(cert_path=str(ca_path))
        if mgr.start() is None:
            return None
        _ca_portal = mgr
    return _ca_portal


@app.get("/api/ca-qr")
async def ca_qr():
    if _ensure_ca_portal() is None:
        return {"error": "CA certificate not found"}
    img = qrcode.make(f"{_ca_base_url()}/")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")


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


@app.get("/api/ca-uninstall")
async def ca_uninstall_page():
    return HTMLResponse(content=CA_UNINSTALL_HTML)


@app.get("/api/ca-uninstall-qr")
async def ca_uninstall_qr():
    if _ensure_ca_portal() is None:
        return {"error": "CA certificate not found"}
    url = f"{_ca_base_url()}/api/ca-uninstall"
    img = qrcode.make(url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    import traceback
    logger.error("Unhandled exception: %s\n%s", exc, traceback.format_exc())
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {exc}"},
    )

from starlette.exceptions import HTTPException as StarletteHTTPException
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    from fastapi.responses import JSONResponse, FileResponse
    if exc.status_code == 404:
        if request.url.path.startswith("/api/") or request.url.path.startswith("/ws/"):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        index_path = FRONTEND_DIST / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
    return JSONResponse(status_code=exc.status_code, content={"detail": str(exc.detail)})


@app.websocket("/ws/traffic")
async def traffic_websocket(ws: WebSocket):
    if ws_manager:
        await ws_manager.connect(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            await ws_manager.disconnect(ws)


from api.routes.sessions import router as sessions_router
from api.routes.requests import router as requests_router
from api.routes.repeater import router as repeater_router, service as repeater_service
from api.routes.scanner import router as scanner_router
from api.routes.decoder import router as decoder_router
from api.routes.match_replace import router as match_replace_router
from api.routes.collaborator import router as collaborator_router
from api.routes.reporter import router as reporter_router
from api.routes.fuzzer import router as fuzzer_router
from api.routes.crawler import router as crawler_router
from api.routes.sequencer import router as sequencer_router
from api.routes.api_inspector import router as api_inspector_router
from api.routes.active_scanner import router as active_scanner_router
from api.routes.interceptor import router as interceptor_router
from api.routes.session_handling import router as session_handling_router
from api.routes.comparer import router as comparer_router
from api.routes.search import router as search_router
from api.routes.auth_testing import router as auth_testing_router
from api.routes.websocket_intercept import router as websocket_intercept_router
from api.routes.plugins import router as plugins_router
from api.routes.projects import router as projects_router
from api.routes.scan_jobs import router as scan_jobs_router
from api.routes.automation import router as automation_router
from api.routes.content_discovery import router as content_discovery_router
from api.routes.organizer import router as organizer_router
from api.routes.inspector import router as inspector_router
from api.routes.clickbandit import router as clickbandit_router
from api.routes.target_scope import router as scope_router
from api.routes.proxy_config import router as proxy_config_router
from api.routes.pipeline import router as pipeline_router
from api.routes.smart_triage import router as triage_router
from api.routes.automations import router as automations_router
from api.routes.live_audit import router as live_audit_router
from api.routes.dashboard import router as dashboard_router
from api.routes.scan_policies import router as scan_policies_router
from api.routes.settings import router as settings_router
from api.routes.mitm import router as mitm_router, init_mitm
from api.routes.proxy import router as proxy_router, init_proxy
from api.routes.auth_scan import router as auth_scan_router, init_auth_scanner
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sys

from api.routes.auto_exploit import router as auto_exploit_router
from api.routes.custom_scanner import router as custom_scanner_router
from api.routes.recommendations import router as recommendations_router, init_recommender
from core.recommender.engine import RecommendationEngine

_env_frontend = os.environ.get("NYX_FRONTEND_DIST")
if _env_frontend:
    FRONTEND_DIST = Path(_env_frontend)
elif getattr(sys, 'frozen', False):
    FRONTEND_DIST = Path(sys.executable).parent.parent / "frontend"
else:
    FRONTEND_DIST = Path(__file__).parent.parent / "frontend" / "dist"

app.include_router(sessions_router)
app.include_router(requests_router)
app.include_router(repeater_router)
app.include_router(scanner_router)
app.include_router(decoder_router)
app.include_router(match_replace_router)
app.include_router(collaborator_router)
app.include_router(reporter_router)
app.include_router(fuzzer_router)
app.include_router(crawler_router)
app.include_router(sequencer_router)
app.include_router(api_inspector_router)
app.include_router(active_scanner_router)
app.include_router(interceptor_router)
app.include_router(session_handling_router)
app.include_router(comparer_router)
app.include_router(search_router)
app.include_router(auth_testing_router)
app.include_router(websocket_intercept_router)
app.include_router(plugins_router)
app.include_router(projects_router)
app.include_router(scan_jobs_router)
app.include_router(automation_router)
app.include_router(content_discovery_router)
app.include_router(organizer_router)
app.include_router(inspector_router)
app.include_router(clickbandit_router)
app.include_router(scope_router)
app.include_router(proxy_config_router)
app.include_router(pipeline_router)
app.include_router(triage_router)
app.include_router(automations_router)
app.include_router(live_audit_router)
app.include_router(dashboard_router)
app.include_router(scan_policies_router)
app.include_router(settings_router)
app.include_router(mitm_router)
app.include_router(proxy_router)
app.include_router(auth_scan_router)
app.include_router(auto_exploit_router)
app.include_router(custom_scanner_router)
app.include_router(recommendations_router)

init_mitm(proxy_engine)
init_proxy(proxy_engine)


@app.get("/health")
async def health():
    return {"status": "ok", "app": "Nyx", "version": "1.0.0"}


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


@app.get("/api/mitm/portal")
async def captive_portal():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(CAPTIVE_PORTAL_HTML)


@app.get("/api/mitm/portal/checkin")
async def portal_checkin(installed: bool = False):
    if installed:
        return {"status": "ok", "message": "CA certificate acknowledged. Traffic interception active."}
    return {"status": "pending", "message": "Install the CA certificate to enable HTTPS decryption."}


@app.get("/api/ca-certificate")
async def download_ca():
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if ca_path.exists():
        return FileResponse(str(ca_path), media_type="application/x-pem-file", filename="mitmproxy-ca-cert.pem")
    return {"error": "CA certificate not found. Start the proxy first."}


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)
