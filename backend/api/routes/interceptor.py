from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.deps import get_db
from core.storage.models import InterceptorRule
from pydantic import BaseModel
import uuid

router = APIRouter(prefix="/api/interceptor", tags=["interceptor"])


class RuleCreate(BaseModel):
    session_id: uuid.UUID | None = None
    name: str
    scope: str = "request"
    intercept_on_match: bool = True
    match_type: str | None = None
    match_pattern: str | None = None
    is_regex: bool = False
    order: int = 0


class RuleUpdate(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    scope: str | None = None
    intercept_on_match: bool | None = None
    match_type: str | None = None
    match_pattern: str | None = None
    is_regex: bool | None = None
    order: int | None = None


class RuleResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID | None
    enabled: bool
    name: str
    scope: str
    intercept_on_match: bool
    match_type: str | None
    match_pattern: str | None
    is_regex: bool
    order: int

    model_config = {"from_attributes": True}


class ForwardModifications(BaseModel):
    method: str | None = None
    url: str | None = None
    headers: dict | None = None
    body: str | None = None


def _get_engine(request: Request):
    engine = getattr(request.app.state, 'interceptor_engine', None)
    if not engine:
        raise HTTPException(503, "Interceptor engine not available")
    return engine


@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InterceptorRule).order_by(InterceptorRule.order))
    return list(result.scalars().all())


@router.post("/rules", response_model=RuleResponse, status_code=201)
async def create_rule(body: RuleCreate, request: Request, db: AsyncSession = Depends(get_db)):
    data = body.model_dump()
    if data.get("session_id") is None:
        from core.storage.models import Session
        result = await db.execute(select(Session).limit(1))
        s = result.scalar_one_or_none()
        if s:
            data["session_id"] = s.id
        else:
            data.pop("session_id", None)
    rule = InterceptorRule(**data)
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    try:
        await _get_engine(request).refresh_rules_cache()
    except Exception:
        pass
    return rule


@router.put("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: uuid.UUID, body: RuleUpdate, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InterceptorRule).where(InterceptorRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(rule, key, value)
    await db.commit()
    await db.refresh(rule)
    try:
        await _get_engine(request).refresh_rules_cache()
    except Exception:
        pass
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InterceptorRule).where(InterceptorRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    try:
        await _get_engine(request).refresh_rules_cache()
    except Exception:
        pass


@router.get("/status")
async def get_interceptor_status(request: Request):
    engine = _get_engine(request)
    return {"enabled": engine.enabled}


@router.post("/toggle")
async def toggle_interceptor(request: Request):
    engine = _get_engine(request)
    engine.enabled = not engine.enabled
    return {"enabled": engine.enabled}


@router.get("/paused")
async def get_paused(request: Request):
    engine = _get_engine(request)
    return engine.get_paused()


@router.post("/forward/{item_id}")
async def forward_item(item_id: str, mods: ForwardModifications | None = None, request: Request = None):
    engine = _get_engine(request)
    try:
        await engine.forward_item(item_id, mods.model_dump(exclude_none=True) if mods else None)
    except ValueError as e:
        raise HTTPException(404, detail=str(e))
    return {"status": "forwarded"}


@router.post("/drop/{item_id}")
async def drop_item(item_id: str, request: Request):
    engine = _get_engine(request)
    try:
        await engine.drop_item(item_id)
    except ValueError as e:
        raise HTTPException(404, detail=str(e))
    return {"status": "dropped"}
