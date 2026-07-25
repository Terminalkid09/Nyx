import asyncio
import logging
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from modules.auth.models import AuthProfile, MacroStep
from modules.auth.store import list_profiles, get_profile, create_profile, update_profile, delete_profile
from modules.scanner.active.scanner import ActiveScanner
from core.storage.database import AsyncSessionLocal
from core.storage.models import Request as CapturedRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["auth"])

_active_scanner: ActiveScanner | None = None


def init_auth_scanner(scanner: ActiveScanner):
    global _active_scanner
    _active_scanner = scanner


class LoginRecordRequest(BaseModel):
    session_id: str
    login_url: str | None = None


class LoginRecordResponse(BaseModel):
    steps: list[MacroStep]
    message: str
    captured_count: int


class AuthenticatedScanRequest(BaseModel):
    profile_id: str
    target_url: str
    params: list[str] = []
    profile: AuthProfile | None = None


@router.post("/login/record", response_model=LoginRecordResponse)
async def record_login(req: LoginRecordRequest):
    """Record login steps from recent proxy traffic for a session."""
    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        stmt = (
            select(CapturedRequest)
            .where(CapturedRequest.session_id == req.session_id)
            .order_by(CapturedRequest.timestamp.asc())
        )
        if req.login_url:
            stmt = stmt.where(CapturedRequest.url.contains(req.login_url))
        result = await db.execute(stmt)
        requests = result.scalars().all()

    if not requests:
        raise HTTPException(status_code=404, detail="No requests found for this session")

    steps = []
    for r in requests[:20]:
        method = r.method or "GET"
        headers = r.headers or {}
        body = r.body or ""

        extract = {}
        if "csrf" in r.url.lower() or "token" in r.url.lower():
            extract["csrf_token"] = r"name=\"csrf_token\" value=\"([^\"]+)\""

        step = MacroStep(
            url=r.url,
            method=method,
            headers=headers if isinstance(headers, dict) else {},
            body=body if isinstance(body, str) else "",
            extract=extract,
        )
        steps.append(step)

    return LoginRecordResponse(
        steps=steps,
        message=f"Recorded {len(steps)} login steps from session traffic",
        captured_count=len(steps),
    )


@router.post("/scan", response_model=dict)
async def auth_scan(req: AuthenticatedScanRequest):
    """Run active scan with authentication context."""
    if _active_scanner is None:
        raise HTTPException(status_code=500, detail="Active scanner not initialized")

    profile = None
    if req.profile_id:
        profile = get_profile(req.profile_id)
        if profile is None:
            raise HTTPException(status_code=404, detail="Auth profile not found")
    elif req.profile:
        profile = req.profile
    else:
        raise HTTPException(status_code=400, detail="Either profile_id or profile must be provided")

    base_request = {
        "method": "GET",
        "url": req.target_url,
        "headers": {"User-Agent": "Nyx-AuthScanner/1.0"},
    }

    try:
        results = await _active_scanner.run_checks(base_request, req.params)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

    if results:
        from modules.auto_exploit.engine import AutoExploitEngine
        engine = AutoExploitEngine()
        exploits = []
        for finding in results[:5]:
            try:
                exploit = engine.generate_exploit(finding)
                if exploit:
                    exploits.append(exploit)
            except Exception:
                continue
    else:
        exploits = []

    return {
        "status": "ok",
        "findings_count": len(results),
        "findings": results,
        "exploits": exploits,
        "profile_used": profile.name if profile else None,
    }


ProfileListResponse = list[AuthProfile]


@router.get("/profiles", response_model=ProfileListResponse)
async def get_profiles():
    return list_profiles()


@router.get("/profiles/{profile_id}", response_model=AuthProfile)
async def get_profile_by_id(profile_id: str):
    profile = get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404)
    return profile


@router.post("/profiles", response_model=AuthProfile)
async def create_profile_endpoint(profile: AuthProfile):
    created = create_profile(profile)
    if not created:
        raise HTTPException(status_code=500, detail="Failed to create profile")
    return created


@router.put("/profiles/{profile_id}", response_model=AuthProfile)
async def update_profile_endpoint(profile_id: str, profile: AuthProfile):
    updated = update_profile(profile_id, profile)
    if not updated:
        raise HTTPException(status_code=404)
    return updated


@router.delete("/profiles/{profile_id}")
async def delete_profile_endpoint(profile_id: str):
    if not delete_profile(profile_id):
        raise HTTPException(status_code=404)
    return {"status": "ok"}
