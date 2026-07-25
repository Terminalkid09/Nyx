import asyncio
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.deps import get_db
from core.storage.models import FuzzJob
from core.events.bus import EventBus
from modules.fuzzer.service import FuzzerService
from pydantic import BaseModel

router = APIRouter(prefix="/api/fuzzer", tags=["fuzzer"])


class PositionConfig(BaseModel):
    name: str
    wordlist_path: str
    processors: list[str] = []


class GrepMatchConfig(BaseModel):
    name: str
    pattern: str
    is_regex: bool = False


class ExtractorConfig(BaseModel):
    name: str
    pattern: str
    is_regex: bool = False
    group: int = 0


class FuzzCreateRequest(BaseModel):
    session_id: uuid.UUID
    base_request_id: uuid.UUID
    request_template: str
    attack_type: str = "sniper"
    positions: list[PositionConfig] = []
    grep_matches: list[GrepMatchConfig] = []
    extractors: list[ExtractorConfig] = []
    rate_limit_rps: int = 10


class PreviewRequest(BaseModel):
    request_template: str
    attack_type: str = "sniper"
    positions: list[PositionConfig] = []


class JobResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    base_request_id: uuid.UUID
    status: str
    total_requests: int
    completed_requests: int
    attack_type: str
    wordlist_name: str
    rate_limit_rps: int
    positions: list[dict] = []
    grep_matches: list[dict] = []
    extractors: list[dict] = []
    request_template: str = ""
    results: list[dict] = []

    model_config = {"from_attributes": True}


_fuzzer_service_instance: FuzzerService | None = None


def get_fuzzer_service(request: Request) -> FuzzerService:
    global _fuzzer_service_instance
    if _fuzzer_service_instance is None:
        event_bus = getattr(request.app.state, 'event_bus', None)
        if not event_bus:
            raise HTTPException(503, detail="Backend not fully initialized")
        # __file__ = backend/api/routes/fuzzer.py → parent.parent.parent = backend/
        backend_dir = Path(__file__).parent.parent.parent
        wordlists_dir = backend_dir / "wordlists"
        _fuzzer_service_instance = FuzzerService(event_bus=event_bus, wordlists_dir=wordlists_dir)
    return _fuzzer_service_instance


@router.get("/jobs", response_model=list[JobResponse])
async def list_jobs(session_id: uuid.UUID | None = None, db: AsyncSession = Depends(get_db)):
    query = select(FuzzJob)
    if session_id:
        query = query.where(FuzzJob.session_id == session_id)
    query = query.order_by(FuzzJob.created_at.desc())
    result = await db.execute(query)
    return [JobResponse.model_validate(j) for j in result.scalars().all()]


@router.post("/jobs", response_model=JobResponse, status_code=201)
async def create_job(body: FuzzCreateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    service = get_fuzzer_service(request)

    positions_data = [p.model_dump() for p in body.positions]
    grep_data = [g.model_dump() for g in body.grep_matches]
    ext_data = [e.model_dump() for e in body.extractors]

    wordlists: dict[str, list[str]] = {}
    for pos in body.positions:
        wl = service.expand_wordlist(pos.wordlist_path)
        if not wl:
            raise HTTPException(400, detail=f"Wordlist '{pos.wordlist_path}' not found or empty for position '{pos.name}'")
        wordlists[pos.name] = wl

    payload_mappings = service.generate_payloads(positions_data, wordlists, body.attack_type)
    total = len(payload_mappings)

    wordlist_name = body.positions[0].wordlist_path if body.positions else ""

    job = FuzzJob(
        session_id=body.session_id,
        base_request_id=body.base_request_id,
        request_template=body.request_template,
        attack_type=body.attack_type,
        wordlist_name=wordlist_name,
        positions=positions_data,
        grep_matches=grep_data,
        extractors=ext_data,
        status="pending",
        total_requests=total,
        rate_limit_rps=body.rate_limit_rps,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    asyncio.create_task(service.run_job(
        job_id=job.id,
        template=body.request_template,
        positions=positions_data,
        wordlists=wordlists,
        attack_type=body.attack_type,
        processors=[],
        grep_matches=grep_data,
        extractors=ext_data,
        rate_limit_rps=body.rate_limit_rps,
    ))

    return JobResponse.model_validate(job)


@router.get("/jobs/{job_id}", response_model=JobResponse)
async def get_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Job not found")
    return JobResponse.model_validate(job)


@router.get("/jobs/{job_id}/results")
async def get_job_results(job_id: uuid.UUID, status_filter: int | None = None, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Job not found")
    results_list = job.results or []
    if status_filter is not None:
        results_list = [r for r in results_list if r.get("status") == status_filter]
    return results_list


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FuzzJob).where(FuzzJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(404, detail="Job not found")
    service = get_fuzzer_service(request)
    service.cancel_job(job_id)
    if job.status == "running" or job.status == "pending":
        job.status = "cancelled"
        await db.commit()
    return {"detail": "Job cancelled"}


@router.get("/wordlists")
async def list_wordlists(request: Request):
    service = get_fuzzer_service(request)
    return service.list_wordlists()


@router.post("/preview")
async def preview_job(body: PreviewRequest, request: Request):
    service = get_fuzzer_service(request)
    positions_data = [p.model_dump() for p in body.positions]
    wordlists: dict[str, list[str]] = {}
    for pos in body.positions:
        wl = service.expand_wordlist(pos.wordlist_path)
        if not wl:
            raise HTTPException(400, detail=f"Wordlist '{pos.wordlist_path}' not found for position '{pos.name}'")
        wordlists[pos.name] = wl
    payloads = service.generate_payloads(positions_data, wordlists, body.attack_type)
    return {"total_requests": len(payloads)}


@router.get("/attack-types")
async def list_attack_types():
    return ["sniper", "batteringram", "pitchfork", "clusterbomb"]


@router.get("/processors")
async def list_processors():
    return [
        "add_prefix:",
        "add_suffix:",
        "url_encode",
        "double_url_encode",
        "base64_encode",
        "hex_encode",
        "hex_decode",
        "unicode_encode",
        "reverse",
        "md5_hash",
        "sha1_hash",
        "sha256_hash",
        "to_upper",
        "to_lower",
    ]
