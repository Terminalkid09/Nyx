import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.deps import get_db
from core.storage.models import TargetScopeRule
from core.scope import check_scope as _check_scope
from pydantic import BaseModel

router = APIRouter(prefix="/api/scope", tags=["target_scope"])


class RuleCreate(BaseModel):
    session_id: uuid.UUID | None = None
    enabled: bool = True
    name: str
    rule_type: str
    pattern: str
    is_regex: bool = False
    match_domain: bool = False
    protocols: list = []
    order: int = 0


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    name: str | None = None
    rule_type: str | None = None
    pattern: str | None = None
    is_regex: bool | None = None
    match_domain: bool | None = None
    protocols: list | None = None
    order: int | None = None


class RuleResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID | None
    enabled: bool
    name: str
    rule_type: str
    pattern: str
    is_regex: bool
    match_domain: bool
    protocols: list
    order: int
    created_at: str

    model_config = {"from_attributes": True}


class CheckScopeBody(BaseModel):
    url: str
    rules: list[dict] | None = None


class CheckScopeResponse(BaseModel):
    in_scope: bool
    matched_rule: str | None = None
    matched_by: str | None = None


class ValidateRegexBody(BaseModel):
    pattern: str


class ValidateRegexResponse(BaseModel):
    valid: bool
    error: str | None = None


DOMAIN_PATTERN_SUGGESTIONS = [
    {"label": "Subdomain match", "pattern": r"^https://[a-z]+\.example\.com", "description": "Match specific subdomain"},
    {"label": "Domain + any path", "pattern": r"^https://example\.com/", "description": "Match domain and all paths"},
    {"label": "Wildcard subdomains", "pattern": r"\.example\.com", "description": "Match any subdomain of example.com"},
    {"label": "API endpoints", "pattern": r"/api/", "description": "Match all API routes"},
    {"label": "Specific path pattern", "pattern": r"/user/\d+/profile", "description": "Match user profile pages"},
]


@router.get("/", response_model=list[RuleResponse])
async def list_rules(session_id: uuid.UUID | None = None, db: AsyncSession = Depends(get_db)):
    q = select(TargetScopeRule)
    if session_id:
        q = q.where(TargetScopeRule.session_id == session_id)
    q = q.order_by(TargetScopeRule.order)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/", response_model=RuleResponse, status_code=201)
async def create_rule(body: RuleCreate, db: AsyncSession = Depends(get_db)):
    rule = TargetScopeRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: uuid.UUID, body: RuleUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TargetScopeRule).where(TargetScopeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(rule, key, value)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TargetScopeRule).where(TargetScopeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()


@router.patch("/{rule_id}/toggle", response_model=RuleResponse)
async def toggle_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(TargetScopeRule).where(TargetScopeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    rule.enabled = not rule.enabled
    await db.commit()
    await db.refresh(rule)
    return rule


@router.post("/check", response_model=CheckScopeResponse)
async def check_scope_endpoint(body: CheckScopeBody, db: AsyncSession = Depends(get_db)):
    if body.rules is not None:
        rules = [TargetScopeRule(**r) for r in body.rules]
    else:
        result = await db.execute(select(TargetScopeRule).order_by(TargetScopeRule.order))
        rules = list(result.scalars().all())
    in_scope, matched_rule, matched_by = _check_scope(body.url, rules)
    return CheckScopeResponse(in_scope=in_scope, matched_rule=matched_rule, matched_by=matched_by)


@router.post("/validate-regex", response_model=ValidateRegexResponse)
async def validate_regex(body: ValidateRegexBody):
    try:
        re.compile(body.pattern)
        return ValidateRegexResponse(valid=True, error=None)
    except re.error as e:
        return ValidateRegexResponse(valid=False, error=str(e))


@router.get("/suggestions")
async def get_pattern_suggestions():
    return DOMAIN_PATTERN_SUGGESTIONS
