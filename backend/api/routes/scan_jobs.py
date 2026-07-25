from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from pydantic import BaseModel
import uuid

from api.deps import get_db
from core.storage.models import ScanJob

router = APIRouter(prefix="/api/scan-jobs", tags=["scan-jobs"])


class ScanJobCreate(BaseModel):
    session_id: uuid.UUID
    scan_type: str = "active"
    target_url: str | None = None
    priority: int = 5
    config: dict = {}


class ScanJobResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    scan_type: str
    target_url: str | None
    config: dict
    status: str
    progress: int
    total_tasks: int
    completed_tasks: int
    priority: int
    created_at: str
    started_at: str | None
    completed_at: str | None

    model_config = {"from_attributes": True}


@router.post("", response_model=ScanJobResponse, status_code=201)
async def create_scan_job(body: ScanJobCreate, db: AsyncSession = Depends(get_db)):
    job = ScanJob(
        session_id=body.session_id,
        scan_type=body.scan_type,
        target_url=body.target_url,
        config={**body.config, "priority": body.priority},
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return _job_to_response(job)


@router.get("", response_model=list[ScanJobResponse])
async def list_scan_jobs(
    status: str | None = Query(None),
    sort_by: str = Query("created_at", regex="^(created_at|priority|status|scan_type)$"),
    order: str = Query("desc", regex="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
):
    query = select(ScanJob)
    if status:
        query = query.where(ScanJob.status == status)
    order_col = getattr(ScanJob, sort_by, ScanJob.created_at)
    if order == "desc":
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())
    result = await db.execute(query)
    return [_job_to_response(j) for j in result.scalars().all()]


@router.get("/queue", response_model=list[ScanJobResponse])
async def get_scan_queue(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.status.in_(["pending", "running"]))
        .order_by(
            text("CAST(config->>'priority' AS INTEGER) DESC NULLS LAST"),
            ScanJob.created_at.asc(),
        )
    )
    return [_job_to_response(j) for j in result.scalars().all()]


@router.get("/{job_id}", response_model=ScanJobResponse)
async def get_scan_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, detail="Scan job not found")
    return _job_to_response(job)


@router.post("/{job_id}/start", response_model=ScanJobResponse)
async def start_scan_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, detail="Scan job not found")
    if job.status not in ("pending", "cancelled"):
        raise HTTPException(400, detail=f"Cannot start job in status '{job.status}'")
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(job)
    return _job_to_response(job)


@router.post("/{job_id}/cancel", response_model=ScanJobResponse)
async def cancel_scan_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, detail="Scan job not found")
    if job.status != "running":
        raise HTTPException(400, detail=f"Cannot cancel job in status '{job.status}'")
    job.status = "cancelled"
    job.completed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(job)
    return _job_to_response(job)


@router.post("/{job_id}/priority", response_model=ScanJobResponse)
async def set_job_priority(job_id: uuid.UUID, priority: int = Query(..., ge=1, le=10), db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(404, detail="Scan job not found")
    cfg = dict(job.config or {})
    cfg["priority"] = priority
    job.config = cfg
    await db.commit()
    await db.refresh(job)
    return _job_to_response(job)


def _job_to_response(job: ScanJob) -> dict:
    return {
        "id": job.id,
        "session_id": job.session_id,
        "scan_type": job.scan_type,
        "target_url": job.target_url,
        "config": job.config,
        "status": job.status,
        "progress": job.progress,
        "total_tasks": job.total_tasks,
        "completed_tasks": job.completed_tasks,
        "priority": (job.config or {}).get("priority", 5),
        "created_at": job.created_at.isoformat() if job.created_at else "",
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }
