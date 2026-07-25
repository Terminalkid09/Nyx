from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import joinedload
from api.deps import get_db
from core.storage.models import OrganizerItem, Request
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/organizer", tags=["organizer"])


class OrganizerCreate(BaseModel):
    session_id: uuid.UUID
    request_id: uuid.UUID | None = None
    title: str
    notes: str | None = None
    tags: list[str] | None = None
    color: str | None = None


class OrganizerUpdate(BaseModel):
    title: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    color: str | None = None
    is_flagged: bool | None = None


class RequestSummary(BaseModel):
    id: uuid.UUID
    method: str
    url: str
    status: int | None

    model_config = {"from_attributes": True}


class OrganizerResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    request_id: uuid.UUID | None
    created_at: datetime
    title: str
    notes: str | None
    tags: list
    color: str | None
    is_flagged: bool
    request: RequestSummary | None = None

    model_config = {"from_attributes": True}


class OrganizerWithRequest(OrganizerResponse):
    request: RequestSummary | None = None


class FromRequestCreate(BaseModel):
    session_id: uuid.UUID
    request_id: uuid.UUID
    title: str | None = None


@router.get("/", response_model=list[OrganizerWithRequest])
async def list_items(
    session_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(OrganizerItem)
        .outerjoin(Request, OrganizerItem.request_id == Request.id)
        .order_by(desc(OrganizerItem.created_at))
    )
    if session_id:
        query = query.where(OrganizerItem.session_id == session_id)
    result = await db.execute(query)
    rows = result.unique().scalars().all()
    items = []
    for item in rows:
        req_summary = None
        if item.request_id:
            req = await db.get(Request, item.request_id)
            if req:
                req_summary = RequestSummary(
                    id=req.id,
                    method=req.method,
                    url=req.url,
                    status=req.response_status,
                )
        items.append(OrganizerWithRequest(
            id=item.id,
            session_id=item.session_id,
            request_id=item.request_id,
            created_at=item.created_at,
            title=item.title,
            notes=item.notes,
            tags=item.tags if item.tags else [],
            color=item.color,
            is_flagged=item.is_flagged,
            request=req_summary,
        ))
    return items


@router.post("/", response_model=OrganizerResponse, status_code=201)
async def create_item(body: OrganizerCreate, db: AsyncSession = Depends(get_db)):
    item = OrganizerItem(
        session_id=body.session_id,
        request_id=body.request_id,
        title=body.title,
        notes=body.notes,
        tags=body.tags or [],
        color=body.color,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return OrganizerResponse(
        id=item.id,
        session_id=item.session_id,
        request_id=item.request_id,
        created_at=item.created_at,
        title=item.title,
        notes=item.notes,
        tags=item.tags if item.tags else [],
        color=item.color,
        is_flagged=item.is_flagged,
    )


@router.get("/{item_id}", response_model=OrganizerWithRequest)
async def get_item(item_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    item = await db.get(OrganizerItem, item_id)
    if not item:
        raise HTTPException(404, detail="Item not found")
    req_summary = None
    if item.request_id:
        req = await db.get(Request, item.request_id)
        if req:
            req_summary = RequestSummary(
                id=req.id, method=req.method, url=req.url, status=req.response_status,
            )
    return OrganizerWithRequest(
        id=item.id,
        session_id=item.session_id,
        request_id=item.request_id,
        created_at=item.created_at,
        title=item.title,
        notes=item.notes,
        tags=item.tags if item.tags else [],
        color=item.color,
        is_flagged=item.is_flagged,
        request=req_summary,
    )


@router.put("/{item_id}", response_model=OrganizerResponse)
async def update_item(item_id: uuid.UUID, body: OrganizerUpdate, db: AsyncSession = Depends(get_db)):
    item = await db.get(OrganizerItem, item_id)
    if not item:
        raise HTTPException(404, detail="Item not found")
    if body.title is not None:
        item.title = body.title
    if body.notes is not None:
        item.notes = body.notes
    if body.tags is not None:
        item.tags = body.tags
    if body.color is not None:
        item.color = body.color
    if body.is_flagged is not None:
        item.is_flagged = body.is_flagged
    await db.commit()
    await db.refresh(item)
    return OrganizerResponse(
        id=item.id,
        session_id=item.session_id,
        request_id=item.request_id,
        created_at=item.created_at,
        title=item.title,
        notes=item.notes,
        tags=item.tags if item.tags else [],
        color=item.color,
        is_flagged=item.is_flagged,
    )


@router.delete("/{item_id}", status_code=204)
async def delete_item(item_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    item = await db.get(OrganizerItem, item_id)
    if not item:
        raise HTTPException(404, detail="Item not found")
    await db.delete(item)
    await db.commit()


@router.post("/{item_id}/duplicate", response_model=OrganizerResponse, status_code=201)
async def duplicate_item(item_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    original = await db.get(OrganizerItem, item_id)
    if not original:
        raise HTTPException(404, detail="Item not found")
    item = OrganizerItem(
        session_id=original.session_id,
        request_id=original.request_id,
        title=f"{original.title} (copy)",
        notes=original.notes,
        tags=original.tags,
        color=original.color,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return OrganizerResponse(
        id=item.id,
        session_id=item.session_id,
        request_id=item.request_id,
        created_at=item.created_at,
        title=item.title,
        notes=item.notes,
        tags=item.tags if item.tags else [],
        color=item.color,
        is_flagged=item.is_flagged,
    )


@router.post("/from-request", response_model=OrganizerResponse, status_code=201)
async def create_from_request(body: FromRequestCreate, db: AsyncSession = Depends(get_db)):
    req = await db.get(Request, body.request_id)
    if not req:
        raise HTTPException(404, detail="Request not found")
    title = body.title or req.url
    item = OrganizerItem(
        session_id=body.session_id,
        request_id=body.request_id,
        title=title,
        notes=None,
        tags=[],
        color=None,
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return OrganizerResponse(
        id=item.id,
        session_id=item.session_id,
        request_id=item.request_id,
        created_at=item.created_at,
        title=item.title,
        notes=item.notes,
        tags=item.tags if item.tags else [],
        color=item.color,
        is_flagged=item.is_flagged,
    )
