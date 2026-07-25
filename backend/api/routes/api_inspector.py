from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from api.deps import get_db
from core.storage.models import Request
from api.schemas.requests import RequestResponse
import uuid

router = APIRouter(prefix="/api/api-inspector", tags=["api-inspector"])


@router.get("/requests", response_model=list[RequestResponse])
async def list_api_requests(
    session_id: uuid.UUID | None = Query(None),
    api_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    query = select(Request).where(Request.api_type.isnot(None)).order_by(desc(Request.timestamp))
    if session_id:
        query = query.where(Request.session_id == session_id)
    if api_type:
        query = query.where(Request.api_type == api_type)
    result = await db.execute(query)
    return [RequestResponse.model_validate(r) for r in result.scalars().all()]
