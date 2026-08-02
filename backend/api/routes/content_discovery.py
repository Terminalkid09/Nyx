import asyncio
import uuid
import logging
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.deps import get_db
from core.storage.models import ContentDiscoveryJob
from core.storage.database import AsyncSessionLocal
from core.storage.traffic import DEFAULT_SESSION_ID
from core.events.bus import EventBus
from modules.content_discovery.service import ContentDiscoveryService
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/content-discovery", tags=["content_discovery"])

_discovery_jobs: dict[str, dict] = {}
_discovery_service_instance: ContentDiscoveryService | None = None


class StartDiscoveryRequest(BaseModel):
    target_url: str
    wordlist_path: str
    extensions: list[str] = [""]
    methods: list[str] = ["GET"]
    throttle_ms: int = 0
    session_id: str | None = None


class StartDiscoveryResponse(BaseModel):
    job_id: str
    status: str = "pending"


class JobStatusResponse(BaseModel):
    job_id: str
    target_url: str = ""
    discovered: list[dict] = []
    total: int = 0
    completed: int = 0
    status: str = ""


def get_discovery_service(request: Request) -> ContentDiscoveryService:
    global _discovery_service_instance
    if _discovery_service_instance is None:
        event_bus = getattr(request.app.state, 'event_bus', None)
        if not event_bus:
            raise HTTPException(503, detail="Backend not fully initialized")
        wordlists_dir = Path(__file__).parent.parent.parent / "wordlists"
        _discovery_service_instance = ContentDiscoveryService(event_bus=event_bus, wordlists_dir=wordlists_dir)
    return _discovery_service_instance


async def _run_discovery_in_background(
    job_id: str,
    body: StartDiscoveryRequest,
    request: Request,
    event_bus: EventBus,
):
    service = get_discovery_service(request)

    async with AsyncSessionLocal() as db:
        try:
            job = await db.get(ContentDiscoveryJob, uuid.UUID(job_id))
            if job:
                job.status = "running"
                await db.commit()

            result = await service.discover(
                target_url=body.target_url,
                wordlist_path=body.wordlist_path,
                extensions=body.extensions,
                methods=body.methods,
                throttle_ms=body.throttle_ms,
                session_id=body.session_id,
            )

            _discovery_jobs[job_id] = {
                "target_url": body.target_url,
                "discovered": result.get("discovered", []),
                "total": result.get("total", 0),
                "completed": result.get("completed", 0),
                "status": result.get("status", "done"),
            }

            job = await db.get(ContentDiscoveryJob, uuid.UUID(job_id))
            if job:
                job.status = result.get("status", "done")
                job.discovered_items = result.get("discovered", [])
                job.total_requests = result.get("total", 0)
                job.completed_requests = result.get("completed", 0)
                await db.commit()
        except Exception as e:
            logger.exception("Content discovery failed: %s", e)
            _discovery_jobs[job_id] = {
                "target_url": body.target_url,
                "discovered": [],
                "total": 0,
                "completed": 0,
                "status": "error",
            }
            job = await db.get(ContentDiscoveryJob, uuid.UUID(job_id))
            if job:
                job.status = "error"
                await db.commit()


@router.post("/start", response_model=StartDiscoveryResponse, status_code=201)
async def start_discovery(body: StartDiscoveryRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        session_uuid = uuid.UUID(body.session_id) if body.session_id else DEFAULT_SESSION_ID
    except ValueError:
        session_uuid = DEFAULT_SESSION_ID
    job = ContentDiscoveryJob(
        session_id=session_uuid,
        target_url=body.target_url,
        status="pending",
        wordlist_path=body.wordlist_path,
        config={
            "extensions": body.extensions,
            "methods": body.methods,
            "throttle_ms": body.throttle_ms,
        },
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    job_id = str(job.id)

    _discovery_jobs[job_id] = {
        "target_url": body.target_url,
        "discovered": [],
        "total": 0,
        "completed": 0,
        "status": "pending",
    }

    event_bus: EventBus = request.app.state.event_bus
    asyncio.create_task(_run_discovery_in_background(job_id, body, request, event_bus))

    return StartDiscoveryResponse(job_id=job_id, status="pending")


@router.get("/status/{job_id}", response_model=JobStatusResponse)
async def get_status(job_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(400, detail="Invalid job ID")

    result = await db.execute(select(ContentDiscoveryJob).where(ContentDiscoveryJob.id == uid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Job not found")

    return JobStatusResponse(
        job_id=str(job.id),
        target_url=job.target_url,
        discovered=job.discovered_items or [],
        total=job.total_requests,
        completed=job.completed_requests,
        status=job.status,
    )


@router.post("/stop/{job_id}")
async def stop_discovery(job_id: str, request: Request):
    service = get_discovery_service(request)
    service.stop(job_id)
    if job_id in _discovery_jobs:
        _discovery_jobs[job_id]["status"] = "cancelled"
    return {"detail": "Discovery cancelled"}


@router.get("/wordlists")
async def list_wordlists(request: Request):
    service = get_discovery_service(request)
    return service.list_wordlists()


@router.get("/jobs")
async def list_jobs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ContentDiscoveryJob).order_by(ContentDiscoveryJob.created_at.desc())
    )
    jobs = result.scalars().all()
    return [
        {
            "job_id": str(j.id),
            "target_url": j.target_url,
            "status": j.status,
            "total": j.total_requests,
            "completed": j.completed_requests,
            "discovered_count": len(j.discovered_items or []),
            "created_at": j.created_at.isoformat() if j.created_at else None,
        }
        for j in jobs
    ]
