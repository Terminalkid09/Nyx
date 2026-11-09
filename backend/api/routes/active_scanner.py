from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from api.deps import ensure_authorized
from core.authorization import authorize
from modules.scanner.active.scanner import ActiveScanner
from modules.scanner.scan_depth import list_depths

router = APIRouter(prefix="/api/active-scanner", tags=["active-scanner"])
scanner = ActiveScanner()


class ActiveScanRequest(BaseModel):
    base_request: dict
    target_params: list[str]
    checks: list[str] | None = None
    depth: str | None = None
    # Mandatory: the scan must be attributed to an engagement so its scope
    # rules (and the findings) cannot escape to an unscoped default session.
    session_id: str
    request_id: str | None = None


class ActiveScanResponse(BaseModel):
    results: list[dict]
    total: int


def get_scanner(request: Request) -> ActiveScanner:
    """Return the application scanner (EventBus wired, findings persisted).

    The module-level instance is only a fallback for unit tests that call the
    route without the full application; using it in production silently
    dropped every finding this endpoint produced.
    """
    return getattr(request.app.state, "active_scanner", None) or scanner


@router.post("/run", response_model=ActiveScanResponse)
async def run_active_scan(body: ActiveScanRequest, request: Request):
    # The scanner also re-checks every probe, but the route must reject a
    # missing/out-of-scope session before any background work or findings
    # are created. ``require_session`` closes the "omit session_id to skip
    # scope" bypass that the live review reproduced.
    decision = await authorize(
        body.session_id, body.base_request.get("url", ""), require_session=True
    )
    ensure_authorized(*decision)

    try:
        # The evidence builder and the scope gate both read the event shape, so
        # the captured request fields travel with the session identifiers.
        event = {
            **body.base_request,
            "session_id": body.session_id,
            "request_id": body.request_id,
        }
        results = await get_scanner(request).run_checks(
            body.base_request,
            body.target_params,
            event=event,
            checks_filter=body.checks,
            depth=body.depth,
        )
        return ActiveScanResponse(results=results, total=len(results))
    except Exception as e:
        raise HTTPException(500, detail=str(e))


@router.get("/depths")
async def get_scan_depths():
    """Return the available scan depth profiles (fast/balanced/deep)."""
    return {"depths": list_depths(), "default": "balanced"}
