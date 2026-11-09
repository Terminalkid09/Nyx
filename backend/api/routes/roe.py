"""Rules-of-Engagement profiles (F-01).

Creating a profile signs it with the process secret. Every active probe is
checked against the active profiles; deleting/editing fields in the database
invalidates the signature and locks the profile out instead of silently
widening the engagement.
"""
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from core.config import settings
from core.roe import (
    invalidate_rate_cache,
    policy_from_model,
    sign_policy,
    verify_policy,
)
from core.storage.models import AuthorizationProfile

router = APIRouter(prefix="/api/roe", tags=["roe"])


class RoECreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    targets: list[str] = Field(min_length=1)
    exclusions: list[str] = []
    window_start: datetime | None = None
    window_end: datetime | None = None
    max_rps: float = Field(default=0.0, ge=0.0)


def _serialize(row: AuthorizationProfile) -> dict:
    policy = policy_from_model(row)
    return {
        "id": policy.id,
        "name": policy.name,
        "targets": list(policy.targets),
        "exclusions": list(policy.exclusions),
        "window_start": policy.window_start.isoformat() if policy.window_start else None,
        "window_end": policy.window_end.isoformat() if policy.window_end else None,
        "max_rps": policy.max_rps,
        "signature": policy.signature,
        "signature_valid": verify_policy(policy, settings.secret_key),
        "active": row.active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("", status_code=201)
async def create_profile(body: RoECreate, db: AsyncSession = Depends(get_db)):
    if body.window_start and body.window_end and body.window_end < body.window_start:
        raise HTTPException(400, "window_end must not precede window_start")

    signature = sign_policy(
        settings.secret_key,
        name=body.name,
        targets=body.targets,
        exclusions=body.exclusions,
        window_start=body.window_start,
        window_end=body.window_end,
        max_rps=body.max_rps,
    )
    row = AuthorizationProfile(
        name=body.name,
        targets=body.targets,
        exclusions=body.exclusions,
        window_start=body.window_start,
        window_end=body.window_end,
        max_rps=body.max_rps,
        signature=signature,
        active=True,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    invalidate_rate_cache()
    return _serialize(row)


@router.get("")
async def list_profiles(db: AsyncSession = Depends(get_db)):
    rows = (
        await db.execute(
            select(AuthorizationProfile).order_by(AuthorizationProfile.created_at)
        )
    ).scalars().all()
    return [_serialize(row) for row in rows]


@router.get("/{profile_id}")
async def get_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    row = await db.get(AuthorizationProfile, profile_id)
    if not row:
        raise HTTPException(404, "Profile not found")
    return _serialize(row)


@router.put("/{profile_id}")
async def update_profile(
    profile_id: uuid.UUID,
    body: RoECreate,
    db: AsyncSession = Depends(get_db),
):
    row = await db.get(AuthorizationProfile, profile_id)
    if not row:
        raise HTTPException(404, "Profile not found")
    if body.window_start and body.window_end and body.window_end < body.window_start:
        raise HTTPException(400, "window_end must not precede window_start")

    row.name = body.name
    row.targets = body.targets
    row.exclusions = body.exclusions
    row.window_start = body.window_start
    row.window_end = body.window_end
    row.max_rps = body.max_rps
    # The engagement terms changed, so the old signature is no longer valid.
    # ``active`` is preserved: editing a profile must not silently reactivate
    # one the operator had switched off.
    row.signature = sign_policy(
        settings.secret_key,
        name=body.name,
        targets=body.targets,
        exclusions=body.exclusions,
        window_start=body.window_start,
        window_end=body.window_end,
        max_rps=body.max_rps,
    )
    await db.commit()
    await db.refresh(row)
    invalidate_rate_cache()
    return _serialize(row)


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(
    profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    row = await db.get(AuthorizationProfile, profile_id)
    if not row:
        raise HTTPException(404, "Profile not found")
    await db.delete(row)
    await db.commit()
    invalidate_rate_cache()
    return Response(status_code=204)


@router.post("/{profile_id}/activate")
async def activate_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    row = await db.get(AuthorizationProfile, profile_id)
    if not row:
        raise HTTPException(404, "Profile not found")
    row.active = True
    await db.commit()
    await db.refresh(row)
    invalidate_rate_cache()
    return _serialize(row)


@router.post("/{profile_id}/deactivate")
async def deactivate_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    row = await db.get(AuthorizationProfile, profile_id)
    if not row:
        raise HTTPException(404, "Profile not found")
    row.active = False
    await db.commit()
    await db.refresh(row)
    invalidate_rate_cache()
    return _serialize(row)


@router.post("/{profile_id}/verify")
async def verify_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    row = await db.get(AuthorizationProfile, profile_id)
    if not row:
        raise HTTPException(404, "Profile not found")
    policy = policy_from_model(row)
    return {
        "id": str(row.id),
        "signature_valid": verify_policy(policy, settings.secret_key),
    }
