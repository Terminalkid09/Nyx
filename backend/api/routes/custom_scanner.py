import uuid
import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel
from api.deps import get_db
from core.storage.models import CustomScannerCheck

router = APIRouter(prefix="/api/scanner/custom", tags=["custom_scanner"])


class CheckCreate(BaseModel):
    name: str
    description: str | None = None
    severity: str = "medium"
    match_type: str = "response_body"
    match_pattern: str
    is_regex: bool = True
    payload: str | None = None


class CheckUpdate(BaseModel):
    enabled: bool | None = None
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    match_type: str | None = None
    match_pattern: str | None = None
    is_regex: bool | None = None
    payload: str | None = None


class CheckResponse(BaseModel):
    id: uuid.UUID
    enabled: bool
    name: str
    description: str | None
    severity: str
    match_type: str
    match_pattern: str
    is_regex: bool
    payload: str | None
    created_at: str

    model_config = {"from_attributes": True}


class CheckRunRequest(BaseModel):
    url: str
    response_body: str
    response_headers: dict = {}


class CheckRunResult(BaseModel):
    check_id: uuid.UUID
    check_name: str
    triggered: bool
    severity: str
    evidence: str | None = None


@router.get("/", response_model=list[CheckResponse])
async def list_checks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CustomScannerCheck).order_by(CustomScannerCheck.created_at.desc()))
    return list(result.scalars().all())


@router.post("/", response_model=CheckResponse, status_code=201)
async def create_check(body: CheckCreate, db: AsyncSession = Depends(get_db)):
    if body.is_regex:
        try:
            re.compile(body.match_pattern)
        except re.error as e:
            raise HTTPException(400, detail=f"Invalid regex: {e}")
    check = CustomScannerCheck(**body.model_dump())
    db.add(check)
    await db.commit()
    await db.refresh(check)
    return check


@router.put("/{check_id}", response_model=CheckResponse)
async def update_check(check_id: uuid.UUID, body: CheckUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CustomScannerCheck).where(CustomScannerCheck.id == check_id))
    check = result.scalar_one_or_none()
    if not check:
        raise HTTPException(404, detail="Check not found")
    if body.match_pattern is not None and (body.is_regex if body.is_regex is not None else check.is_regex):
        try:
            re.compile(body.match_pattern)
        except re.error as e:
            raise HTTPException(400, detail=f"Invalid regex: {e}")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(check, key, value)
    await db.commit()
    await db.refresh(check)
    return check


@router.delete("/{check_id}", status_code=204)
async def delete_check(check_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    await db.execute(delete(CustomScannerCheck).where(CustomScannerCheck.id == check_id))
    await db.commit()


@router.post("/run", response_model=list[CheckRunResult])
async def run_custom_checks(body: CheckRunRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CustomScannerCheck).where(CustomScannerCheck.enabled == True))
    checks = list(result.scalars().all())
    if not checks:
        return []

    outcomes = []
    for check in checks:
        triggered = False
        evidence = None
        target = ""
        if check.match_type == "response_body":
            target = body.response_body or ""
        elif check.match_type == "url":
            target = body.url
        elif check.match_type == "response_headers":
            target = str(body.response_headers)

        if check.is_regex:
            try:
                match = re.search(check.match_pattern, target)
                if match:
                    triggered = True
                    evidence = match.group(0)[:200]
            except re.error:
                pass
        else:
            if check.match_pattern in target:
                triggered = True
                evidence = check.match_pattern

        outcomes.append(CheckRunResult(
            check_id=check.id,
            check_name=check.name,
            triggered=triggered,
            severity=check.severity,
            evidence=evidence,
        ))
    return outcomes
