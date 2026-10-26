from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from modules.scanner.active.scanner import ActiveScanner
from modules.scanner.scan_depth import list_depths

router = APIRouter(prefix="/api/active-scanner", tags=["active-scanner"])
scanner = ActiveScanner()


class ActiveScanRequest(BaseModel):
    base_request: dict
    target_params: list[str]
    checks: list[str] | None = None
    depth: str | None = None
    session_id: str | None = None
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
