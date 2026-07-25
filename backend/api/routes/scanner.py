from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_db
from api.schemas.findings import FindingResponse, FindingListResponse
from core.storage.crud.findings import list_findings
import uuid

router = APIRouter(prefix="/api/findings", tags=["scanner"])


@router.get("", response_model=FindingListResponse)
async def list_all_findings(
    session_id: uuid.UUID | None = Query(None),
    severity: str | None = Query(None),
    module: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    items, total = await list_findings(
        db,
        session_id=session_id,
        severity=severity,
        module=module,
        page=page,
        per_page=per_page,
    )
    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in items],
        total=total,
        page=page,
        per_page=per_page,
    )
