from fastapi import APIRouter, HTTPException
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


class ActiveScanResponse(BaseModel):
    results: list[dict]
    total: int


@router.post("/run", response_model=ActiveScanResponse)
async def run_active_scan(body: ActiveScanRequest):
    try:
        results = await scanner.run_checks(
            body.base_request,
            body.target_params,
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
