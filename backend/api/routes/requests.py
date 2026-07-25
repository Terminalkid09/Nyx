from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_db
from api.schemas.requests import RequestResponse, RequestListResponse
from core.storage.crud.requests import get_request, list_requests
import uuid

router = APIRouter(prefix="/api/requests", tags=["requests"])


@router.get("", response_model=RequestListResponse)
async def list_all_requests(
    session_id: uuid.UUID | None = Query(None),
    host: str | None = Query(None),
    method: str | None = Query(None),
    status: int | None = Query(None),
    search: str | None = Query(None),
    flagged: bool | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    items, total = await list_requests(
        db,
        session_id=session_id,
        host=host,
        method=method,
        status=status,
        search=search,
        flagged=flagged,
        page=page,
        per_page=per_page,
    )
    return RequestListResponse(
        items=[RequestResponse.model_validate(r) for r in items],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/{request_id}", response_model=RequestResponse)
async def get_request_by_id(request_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    req = await get_request(db, request_id)
    if not req:
        raise HTTPException(404, detail="Request not found")
    return RequestResponse.model_validate(req)
