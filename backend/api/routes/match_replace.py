import re
import uuid
import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.deps import get_db
from core.storage.models import MatchReplaceRule
from pydantic import BaseModel

router = APIRouter(prefix="/api/match-replace", tags=["match_replace"])


class RuleCreate(BaseModel):
    session_id: uuid.UUID | None = None
    enabled: bool = True
    name: str
    scope: str = "request"
    match_type: str = "string"
    match_pattern: str
    is_regex: bool = False
    replacement: str = ""
    order: int = 0


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    name: str | None = None
    scope: str | None = None
    match_type: str | None = None
    match_pattern: str | None = None
    is_regex: bool | None = None
    replacement: str | None = None
    order: int | None = None


class RuleResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID | None
    enabled: bool
    name: str
    scope: str
    match_type: str
    match_pattern: str
    is_regex: bool
    replacement: str
    order: int

    model_config = {"from_attributes": True}


class ReorderItem(BaseModel):
    id: uuid.UUID
    order: int


class TestInput(BaseModel):
    input_text: str


class TestResult(BaseModel):
    replaced_text: str
    match_count: int


import logging

logger = logging.getLogger(__name__)


def _refresh_match_replace(request: Request):
    try:
        engine = request.app.state.match_replace_engine
        try:
            asyncio.ensure_future(engine.refresh_rules())
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.create_task(engine.refresh_rules())
    except Exception:
        logger.warning("Failed to refresh match-replace rules", exc_info=True)


@router.get("/", response_model=list[RuleResponse])
async def list_rules(
    session_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(MatchReplaceRule).order_by(MatchReplaceRule.order)
    if session_id:
        stmt = stmt.where(MatchReplaceRule.session_id == session_id)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post("/", response_model=RuleResponse, status_code=201)
async def create_rule(body: RuleCreate, request: Request, db: AsyncSession = Depends(get_db)):
    rule = MatchReplaceRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    _refresh_match_replace(request)
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    body: RuleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(MatchReplaceRule).where(MatchReplaceRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(rule, key, value)
    await db.commit()
    await db.refresh(rule)
    _refresh_match_replace(request)
    return rule


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(MatchReplaceRule).where(MatchReplaceRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    _refresh_match_replace(request)


@router.patch("/{rule_id}/toggle", response_model=RuleResponse)
async def toggle_rule(rule_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(MatchReplaceRule).where(MatchReplaceRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    rule.enabled = not rule.enabled
    await db.commit()
    await db.refresh(rule)
    _refresh_match_replace(request)
    return rule


@router.patch("/reorder", response_model=list[RuleResponse])
async def reorder_rules(
    items: list[ReorderItem],
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    updated = []
    for item in items:
        result = await db.execute(
            select(MatchReplaceRule).where(MatchReplaceRule.id == item.id)
        )
        rule = result.scalar_one_or_none()
        if rule:
            rule.order = item.order
            updated.append(rule)
    await db.commit()
    for rule in updated:
        await db.refresh(rule)
    _refresh_match_replace(request)
    return updated


@router.put("/{rule_id}/test", response_model=TestResult)
async def test_rule(
    rule_id: uuid.UUID,
    body: TestInput,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(MatchReplaceRule).where(MatchReplaceRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")

    text = body.input_text
    if rule.is_regex:
        try:
            replaced, count = re.subn(rule.match_pattern, rule.replacement, text)
        except re.error as e:
            raise HTTPException(400, detail=f"Regex error: {e}")
    else:
        count = text.count(rule.match_pattern)
        replaced = text.replace(rule.match_pattern, rule.replacement)

    return TestResult(replaced_text=replaced, match_count=count)
