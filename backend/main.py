import asyncio
import logging
import os
import threading
import time as _time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from core.config import settings
from core.events.bus import EventBus
from core.proxy.engine import ProxyEngine
from core.storage.database import init_db
from core.storage.traffic import TrafficStorageService, ensure_default_session, DEFAULT_SESSION_ID
from api.websocket.manager import WebSocketManager

# Structured JSON logging (env LOG_FORMAT=json). Plain text by default.
if os.environ.get("LOG_FORMAT", "").lower() == "json":
    import json as _json
    from datetime import timezone as _tz

    class _JsonFormatter(logging.Formatter):
        def format(self, record):
            return _json.dumps({
                "ts": datetime.fromtimestamp(record.created, tz=_tz.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "msg": record.getMessage(),
            }, default=str)

    _handler = logging.StreamHandler()
    _handler.setFormatter(_JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[_handler])
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Used by the /health endpoint for uptime reporting.
_START_TIME = _time.time()

event_bus = EventBus()
proxy_engine = ProxyEngine(event_bus, host=settings.PROXY_HOST, port=settings.PROXY_PORT, mode=settings.PROXY_MODE)
ws_manager: WebSocketManager | None = None
_shutdown_event = threading.Event()

_ca_portal = None


def _ensure_ca_portal():
    """Start the CA portal server on demand (lazily, never at boot).

    The CA portal is a separate server (bound to 0.0.0.0) so LAN targets can
    download/remove the CA without touching the localhost-only API.
    """
    global _ca_portal
    from pathlib import Path
    from modules.ca_portal import CAPortalManager
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not ca_path.exists():
        return None
    if _ca_portal is None or not getattr(_ca_portal, "running", False):
        mgr = CAPortalManager(cert_path=str(ca_path))
        if mgr.start() is None:
            return None
        _ca_portal = mgr
    return _ca_portal


@asynccontextmanager
async def lifespan(app: FastAPI):
    global ws_manager
    # Import core.audit BEFORE init_db() so its AuditRecord model is
    # registered on Base.metadata — otherwise create_all won't create the
    # audit_trail table and the audit worker fails with "no such table".
    import core.audit  # noqa: F401

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

    # Start the CA portal now that the proxy has generated the CA — targets can
    # reach http://<nyx-ip>:18081/ to install/remove the CA without touching
    # the app UI. A keep-alive thread prevents the idle watchdog from stopping
    # it while Nyx is open; it exits cleanly on shutdown via _shutdown_event.
    from modules.ca_portal import CAPortalManager
    _ca_portal = _ensure_ca_portal()
    app.state.ca_portal = _ca_portal
    if _ca_portal is not None:
        def _portal_keepalive():
            while not _shutdown_event.wait(timeout=30):
                try:
                    _ca_portal.bump()
                except Exception:
                    return
        threading.Thread(target=_portal_keepalive, name="ca-portal-keepalive", daemon=True).start()
        logger.info("CA portal listening on 0.0.0.0:%s (LAN targets can install/remove the CA anytime)", _ca_portal.lan_port)

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

    # ── Audit trail ───────────────────────────────────────────────────
    from core.audit import start_audit_trail, log_audit
    start_audit_trail()
    log_audit(action="nyx.started", detail=f"Version 1.0.0 — proxy {settings.PROXY_HOST}:{settings.PROXY_PORT}")
    app.state.log_audit = log_audit

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
    _shutdown_event.set()
    _shutdown_started.set()
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
    # Dispose the SQLAlchemy async engine pool — without this, repeated
    # restarts accumulate file descriptors until the OS runs out.
    from core.storage.database import engine as _db_engine
    try:
        await _db_engine.dispose()
        logger.info("Database engine pool disposed")
    except Exception as e:
        logger.warning("Database engine disposal failed: %s", e)
    from core.audit import stop_audit_trail, log_audit
    log_audit(action="nyx.stopped", result="success")
    stop_audit_trail()
    logger.info("Shutdown complete.")


app = FastAPI(lifespan=lifespan)
app.state._start_time = _START_TIME

# ── Guaranteed network-state cleanup ─────────────────────────────────────────
# The OS-level state Nyx touches (IP forwarding, WinDivert driver, firewall
# rules, system proxy) MUST never outlive the process — a force-killed backend
# that leaves IP forwarding enabled blackholes the machine's own traffic and
# keeps targets routed into a dead gateway. Three independent safety nets:
#   1. POST /api/shutdown  → graceful path used by the Electron shell on quit
#   2. signal handlers     → Ctrl+C / SIGTERM (console close)
#   3. atexit              → normal interpreter exit
_shutdown_started = threading.Event()


def _emergency_cleanup() -> None:
    """Synchronous best-effort cleanup of everything that touches the OS."""
    if _shutdown_started.is_set():
        return
    _shutdown_started.set()
    logger.warning("Emergency cleanup: stopping WinDivert, disabling IP forwarding, clearing system proxy")
    try:
        proxy_engine.stop()
    except Exception as e:
        logger.error("Emergency cleanup failed for the proxy engine: %s", e)
    # Synchronous engine disposal (atexit/signal cannot await). This leaks
    # a handful of file descriptors on emergency exit but prevents a full
    # crash-loop fd exhaustion on normal restart cycles.
    from core.storage.database import engine as _db_engine
    try:
        import asyncio as _asyncio
        _loop = _asyncio.new_event_loop()
        _loop.run_until_complete(_db_engine.dispose())
        _loop.close()
    except Exception as _e:
        pass
    # Flush any pending audit records so they are not lost on crash/force-kill.
    from core.audit import flush_audit_sync
    flush_audit_sync()


async def _full_shutdown_cleanup() -> None:
    """Graceful teardown of MITM resources + OS state (idempotent)."""
    if _shutdown_started.is_set():
        return
    _shutdown_started.set()
    from api.routes.mitm import shutdown_mitm

    try:
        await shutdown_mitm()
    except Exception as e:
        logger.warning("shutdown_mitm during app shutdown failed: %s", e)
    proxy_engine.stop()


def _begin_delayed_exit(delay: float = 0.5) -> None:
    """Schedule a delayed graceful shutdown then exit.

    Must be called from within a running asyncio event loop (e.g. from an
    async FastAPI handler).
    """
    async def _exit_soon():
        await asyncio.sleep(delay)
        try:
            await _full_shutdown_cleanup()
        finally:
            os._exit(0)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_exit_soon())
    except RuntimeError:
        # Called from a non-async context (e.g. signal handler or thread).
        # Fall back to emergency synchronous cleanup.
        logger.warning("Delayed exit called without a running event loop — using emergency cleanup")
        _emergency_cleanup()
        os._exit(0)


@app.post("/api/shutdown")
async def request_shutdown(request: Request):
    """Ask the backend to flush all network state and exit.

    Localhost-only: the Electron shell calls this on quit so the backend can
    release IP forwarding / firewall rules cleanly instead of being killed.
    """
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Shutdown endpoint is localhost-only")
    logger.info("Shutdown requested via API — flushing network state and exiting")
    _begin_delayed_exit()
    return {"status": "shutting_down"}


def _signal_handler(signum, _frame):
    logger.warning("Received signal %s — running emergency cleanup", signum)
    _emergency_cleanup()
    os._exit(0)


import atexit as _atexit
import signal as _signal

# Records which signals got a cleanup handler — lets tests verify wiring
# without poking the live handler registry (pytest owns SIGINT too).
_SIGNAL_HANDLERS_REGISTERED: list[str] = []

_atexit.register(_emergency_cleanup)
for _sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
    _sig = getattr(_signal, _sig_name, None)
    if _sig is not None:
        try:
            _signal.signal(_sig, _signal_handler)
            _SIGNAL_HANDLERS_REGISTERED.append(_sig_name)
        except (ValueError, OSError):
            pass

from core.api_auth import verify_api_key
app.middleware("http")(verify_api_key)

from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from api.routes.system import router as system_router
app.include_router(system_router)

# Keep a reference to the CA portal manager for system.py to use
_ca_portal = None


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    import traceback
    import uuid as _uuid

    from core.metrics import registry as _metrics
    _metrics.inc("http_errors_5xx_total")

    request_id = str(_uuid.uuid4())[:8]
    logger.error(
        "Unhandled exception [%s] %s %s: %s\n%s",
        request_id,
        request.method,
        request.url.path,
        exc,
        traceback.format_exc(),
    )
    from fastapi.responses import JSONResponse

    # Never leak internal exception details to the client — they can expose
    # filesystem paths, SQL fragments and library versions. The full traceback
    # is in the server log, correlated by request_id.
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
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
    from core.api_auth import validate_ws_origin

    if not validate_ws_origin(ws):
        # Foreign origin (another web page scripting this socket) — refuse the
        # upgrade before accepting, so no traffic is ever streamed to it.
        logger.warning("Rejected WebSocket connection from foreign origin: %s", ws.headers.get("origin", ""))
        await ws.close(code=1008)
        return
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
from api.routes.auth_scan import router as auth_scan_router
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import sys

from api.routes.auto_exploit import router as auto_exploit_router
from api.routes.custom_scanner import router as custom_scanner_router
from api.routes.recommendations import router as recommendations_router, init_recommender
from api.routes.compliance import router as compliance_router
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
app.include_router(compliance_router)

from api.routes.backup import router as backup_router
app.include_router(backup_router)

init_mitm(proxy_engine)
init_proxy(proxy_engine)


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.API_HOST, port=settings.API_PORT)
