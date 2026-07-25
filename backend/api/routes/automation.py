from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/automation", tags=["automation"])


class AutoScanConfigUpdate(BaseModel):
    auto_active_scan: bool | None = None
    max_concurrent: int | None = None
    scan_delay_ms: int | None = None


@router.get("/discovered")
async def get_discovered(request: Request):
    engine = getattr(request.app.state, 'auto_scan_engine', None)
    if not engine:
        raise HTTPException(503, detail="AutoScanEngine not available")
    return engine.get_discovered_urls()


@router.get("/pending")
async def get_pending(request: Request):
    engine = getattr(request.app.state, 'auto_scan_engine', None)
    if not engine:
        raise HTTPException(503, detail="AutoScanEngine not available")
    return engine.get_pending_scans()


@router.post("/config")
async def update_config(body: AutoScanConfigUpdate, request: Request):
    engine = getattr(request.app.state, 'auto_scan_engine', None)
    if not engine:
        raise HTTPException(503, detail="AutoScanEngine not available")
    engine.update_config(body.model_dump(exclude_none=True))
    return engine.get_config()


@router.get("/config")
async def get_config(request: Request):
    engine = getattr(request.app.state, 'auto_scan_engine', None)
    if not engine:
        raise HTTPException(503, detail="AutoScanEngine not available")
    return engine.get_config()
