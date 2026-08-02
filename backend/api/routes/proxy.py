from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from core.proxy.engine import ProxyEngine
import uuid

router = APIRouter(prefix="/api/proxy", tags=["proxy"])

_engine: ProxyEngine | None = None


def init_proxy(engine: ProxyEngine):
    global _engine
    _engine = engine


@router.get("/capture")
async def get_capture_status():
    if not _engine:
        return {"capture_active": True}
    return {"capture_active": _engine.capture_active}


class CaptureToggle(BaseModel):
    active: bool


@router.post("/capture")
async def set_capture_status(body: CaptureToggle):
    if not _engine:
        return {"capture_active": True}
    _engine.capture_active = body.active
    return {"capture_active": _engine.capture_active}


class SessionSwitch(BaseModel):
    session_id: str


@router.patch("/session")
async def set_proxy_session(body: SessionSwitch):
    """Update which session_id the proxy engine stamps on captured traffic."""
    if not _engine:
        raise HTTPException(503, detail="Proxy engine not initialized")
    try:
        uuid.UUID(body.session_id)  # validate format
    except ValueError:
        raise HTTPException(400, detail="Invalid session_id format")
    _engine.current_session_id = body.session_id
    return {"session_id": _engine.current_session_id}


@router.get("/session")
async def get_proxy_session():
    """Return the current session_id the proxy engine is using."""
    if not _engine:
        return {"session_id": None}
    return {"session_id": _engine.current_session_id}
