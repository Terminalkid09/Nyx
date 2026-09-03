import uuid
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from modules.crawler.service import CrawlerService
from core.events.bus import EventBus

event_bus = EventBus()

router = APIRouter(prefix="/api/crawler", tags=["crawler"])

_crawl_jobs: dict[str, dict] = {}


class LoginMacroStep(BaseModel):
    url: str
    method: str = "GET"
    body: Optional[str] = None
    headers: dict[str, str] = {}


class CrawlStartRequest(BaseModel):
    start_url: str
    max_depth: int = 3
    max_pages: int = 50
    scope_include: list[str] = []
    scope_exclude: list[str] = []
    form_fill_config: dict[str, str] = {}
    login_macro: list[LoginMacroStep] = []
    headers: dict[str, str] = {}
    respect_robots_txt: bool = True


class CrawlJobResponse(BaseModel):
    id: str
    start_url: str
    status: str
    progress: int
    max_pages: int
    discovered_urls: list[str]
    discovered_forms: list[dict]
    created_at: str


class CrawlStatusResponse(BaseModel):
    job_id: str
    status: str
    discovered_urls: list[str] = []
    forms_found: list[dict] = []
    pages_visited: int = 0
    message: str = ""


class CrawlFormResponse(BaseModel):
    job_id: str
    forms: list[dict] = []


def _run_crawl_in_background(job_id: str, body: CrawlStartRequest):
    async def crawl_task():
        try:
            crawler = CrawlerService(event_bus)
            _crawl_jobs[job_id]["crawler_service"] = crawler

            # Subscribe to real-time progress updates
            async def on_progress(evt: dict):
                if evt.get("job_id") == job_id:
                    _crawl_jobs[job_id]["progress"] = evt.get("pages_visited", 0)
                    _crawl_jobs[job_id]["discovered_urls"] = evt.get("discovered_urls", [])
                    _crawl_jobs[job_id]["discovered_forms"] = evt.get("forms_found", [])
            event_bus.subscribe("crawl.progress", on_progress)

            result = await crawler.crawl(
                start_url=body.start_url,
                max_depth=body.max_depth,
                max_pages=body.max_pages,
                scope_include=body.scope_include,
                scope_exclude=body.scope_exclude,
                form_fill_config=body.form_fill_config,
                login_macro=[s.model_dump() for s in body.login_macro],
                headers=body.headers,
                respect_robots_txt=body.respect_robots_txt,
                job_id=job_id,
            )
            _crawl_jobs[job_id] = {
                "id": job_id,
                "start_url": body.start_url,
                "status": result["status"],
                "progress": result["pages_visited"],
                "max_pages": body.max_pages,
                "discovered_urls": result["discovered_urls"],
                "discovered_forms": result["forms_found"],
                "created_at": _crawl_jobs[job_id].get("created_at", datetime.now(timezone.utc).isoformat()),
            }
        except Exception as e:
            _crawl_jobs[job_id] = {
                "id": job_id,
                "start_url": body.start_url,
                "status": "failed",
                "progress": _crawl_jobs[job_id].get("progress", 0),
                "max_pages": body.max_pages,
                "discovered_urls": _crawl_jobs[job_id].get("discovered_urls", []),
                "discovered_forms": _crawl_jobs[job_id].get("discovered_forms", []),
                "created_at": _crawl_jobs[job_id].get("created_at", datetime.now(timezone.utc).isoformat()),
                "error": str(e),
            }

    asyncio.create_task(crawl_task())


@router.post("/start")
async def start_crawl(body: CrawlStartRequest):
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    _crawl_jobs[job_id] = {
        "id": job_id,
        "start_url": body.start_url,
        "status": "running",
        "progress": 0,
        "max_pages": body.max_pages,
        "discovered_urls": [],
        "discovered_forms": [],
        "created_at": now,
    }

    _run_crawl_in_background(job_id, body)

    return CrawlJobResponse(
        id=job_id,
        start_url=body.start_url,
        status="running",
        progress=0,
        max_pages=body.max_pages,
        discovered_urls=[],
        discovered_forms=[],
        created_at=now,
    )


@router.get("/status/{job_id}")
async def crawl_status(job_id: str):
    job = _crawl_jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Job not found")
    discovered_urls = job.get("discovered_urls", [])
    forms_found = job.get("discovered_forms", [])
    pages_visited = job.get("progress", 0)
    return CrawlStatusResponse(
        job_id=job_id,
        status=job.get("status", "unknown"),
        discovered_urls=discovered_urls,
        forms_found=forms_found,
        pages_visited=pages_visited,
        message=f"Discovered {len(discovered_urls)} URLs, {len(forms_found)} forms, {pages_visited} pages crawled",
    )


@router.post("/stop/{job_id}")
async def stop_crawl(job_id: str):
    job = _crawl_jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Job not found")
    if job.get("status") not in ("running", "pending"):
        raise HTTPException(400, detail=f"Job is {job.get('status')}, not running")

    job["crawler_service"].stop(job_id)
    job["status"] = "stopped"
    return {"job_id": job_id, "status": "stopped"}


@router.get("/jobs")
async def list_crawl_jobs():
    result = []
    for jid in _crawl_jobs:
        job = {k: v for k, v in _crawl_jobs[jid].items() if not isinstance(v, CrawlerService)}
        result.append(job)
    return result


@router.get("/forms/{job_id}")
async def get_crawl_forms(job_id: str):
    job = _crawl_jobs.get(job_id)
    if not job:
        raise HTTPException(404, detail="Job not found")
    return CrawlFormResponse(
        job_id=job_id,
        forms=job.get("discovered_forms", []),
    )
