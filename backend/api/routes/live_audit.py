from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/live-audit", tags=["live_audit"])


class LiveAuditConfigUpdate(BaseModel):
    passive_scan: bool | None = None
    active_scan: bool | None = None
    param_discovery: bool | None = None
    fuzz_discovered: bool | None = None
    max_concurrent_audits: int | None = None
    scope_only: bool | None = None
    throttle_ms: int | None = None
    log_all: bool | None = None


def get_service(request: Request):
    service = getattr(request.app.state, "live_audit_service", None)
    if not service:
        raise HTTPException(503, detail="LiveAuditService not available")
    return service


@router.get("/status")
async def get_status(request: Request):
    return get_service(request).get_status()


@router.post("/start")
async def start(request: Request):
    await get_service(request).start()
    return {"status": "started"}


@router.post("/stop")
async def stop(request: Request):
    await get_service(request).stop()
    return {"status": "stopped"}


@router.put("/config")
async def update_config(body: LiveAuditConfigUpdate, request: Request):
    service = get_service(request)
    service.update_config(body.model_dump(exclude_none=True))
    return service.get_config()


@router.get("/config")
async def get_config(request: Request):
    return get_service(request).get_config()


@router.post("/clear-stats")
async def clear_stats(request: Request):
    get_service(request).clear_stats()
    return {"status": "cleared"}


@router.post("/clear-log")
async def clear_log(request: Request):
    get_service(request).clear_log()
    return {"status": "cleared"}
