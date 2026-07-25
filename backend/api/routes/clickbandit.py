from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.deps import get_db
from core.storage.models import ClickbanditConfig
from modules.clickbandit.service import ClickbanditService
from pydantic import BaseModel
import uuid

router = APIRouter(prefix="/api/clickbandit", tags=["clickbandit"])

service = ClickbanditService()


class ClickbanditCreate(BaseModel):
    session_id: uuid.UUID
    name: str
    target_url: str
    layers: list = []
    config: dict = {}


class ClickbanditUpdate(BaseModel):
    name: str | None = None
    target_url: str | None = None
    layers: list | None = None
    config: dict | None = None


class ClickbanditResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    name: str
    target_url: str
    created_at: str
    updated_at: str
    layers: list
    config: dict

    model_config = {"from_attributes": True}


class GenerateBody(BaseModel):
    target_url: str
    layers: list = []
    config: dict = {}


@router.get("/", response_model=list[ClickbanditResponse])
async def list_configs(session_id: uuid.UUID | None = None, db: AsyncSession = Depends(get_db)):
    q = select(ClickbanditConfig)
    if session_id:
        q = q.where(ClickbanditConfig.session_id == session_id)
    q = q.order_by(ClickbanditConfig.created_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/", response_model=ClickbanditResponse, status_code=201)
async def create_config(body: ClickbanditCreate, db: AsyncSession = Depends(get_db)):
    if not service.validate_url(body.target_url):
        raise HTTPException(400, detail="Invalid target URL. Must be http or https.")
    cfg = ClickbanditConfig(**body.model_dump())
    db.add(cfg)
    await db.commit()
    await db.refresh(cfg)
    return cfg


@router.get("/{config_id}", response_model=ClickbanditResponse)
async def get_config(config_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ClickbanditConfig).where(ClickbanditConfig.id == config_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        raise HTTPException(404, detail="Config not found")
    return cfg


@router.put("/{config_id}", response_model=ClickbanditResponse)
async def update_config(config_id: uuid.UUID, body: ClickbanditUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ClickbanditConfig).where(ClickbanditConfig.id == config_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        raise HTTPException(404, detail="Config not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(cfg, key, value)
    await db.commit()
    await db.refresh(cfg)
    return cfg


@router.delete("/{config_id}", status_code=204)
async def delete_config(config_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ClickbanditConfig).where(ClickbanditConfig.id == config_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        raise HTTPException(404, detail="Config not found")
    await db.delete(cfg)
    await db.commit()


@router.post("/{config_id}/generate")
async def generate_from_config(config_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ClickbanditConfig).where(ClickbanditConfig.id == config_id))
    cfg = result.scalar_one_or_none()
    if not cfg:
        raise HTTPException(404, detail="Config not found")
    html = service.generate_poc(cfg.target_url, cfg.layers, cfg.config)
    return {"html": html, "url": cfg.target_url}


@router.post("/generate")
async def generate_direct(body: GenerateBody):
    if not service.validate_url(body.target_url):
        raise HTTPException(400, detail="Invalid target URL. Must be http or https.")
    html = service.generate_poc(body.target_url, body.layers, body.config)
    return {"html": html, "url": body.target_url}
