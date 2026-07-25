import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from sqlalchemy.orm import selectinload

from api.deps import get_db
from core.storage.models import Finding, Request

router = APIRouter(prefix="/api/triage", tags=["triage"])


@router.get("/findings/grouped")
async def get_grouped_findings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).options(selectinload(Finding.request)).order_by(Finding.created_at.desc())
    )
    findings = result.scalars().all()

    groups: dict[str, dict] = {}
    for f in findings:
        path = f.request.path if f.request else "/unknown"
        key = f"{f.title}@{path}"
        if key not in groups:
            groups[key] = {
                "key": key,
                "title": f.title,
                "severity": f.severity.value,
                "count": 0,
                "endpoint": path,
                "vuln_type": f.title,
                "evidence_preview": (f.evidence or "")[:200],
                "first_seen": f.created_at.isoformat() if f.created_at else "",
                "last_seen": f.created_at.isoformat() if f.created_at else "",
            }
        g = groups[key]
        g["count"] += 1
        if f.evidence and not g["evidence_preview"]:
            g["evidence_preview"] = f.evidence[:200]
        seen = f.created_at.isoformat() if f.created_at else ""
        if seen < g["first_seen"]:
            g["first_seen"] = seen
        if seen > g["last_seen"]:
            g["last_seen"] = seen

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_groups = sorted(groups.values(), key=lambda g: severity_order.get(g["severity"], 99))
    return {"groups": sorted_groups}


@router.get("/findings/{finding_id}/retest")
async def retest_finding(finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, detail="Finding not found")

    req = await db.get(Request, finding.request_id)
    if not req:
        raise HTTPException(400, detail="Associated request not found")

    import httpx
    try:
        async with httpx.AsyncClient() as client:
            method = req.method.lower()
            headers = dict(req.request_headers or {})
            body = req.request_body
            resp = await client.request(method, req.url, headers=headers, content=body, timeout=10, follow_redirects=False)
            evidence = f"Re-ran {req.method} {req.url} -> {resp.status_code} ({len(resp.content)} bytes)"

            is_fixed = resp.status_code != req.response_status if req.response_status else False
            result = "confirmed"
            if is_fixed:
                result = "fixed"

            return {"result": result, "evidence": evidence, "status_code": resp.status_code}
    except Exception as e:
        return {"result": "error", "evidence": str(e)}


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    total_findings_result = await db.execute(select(func.count(Finding.id)))
    total_findings = total_findings_result.scalar() or 0

    all_sev_result = await db.execute(select(Finding.severity))
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in all_sev_result.all():
        s = row[0]
        sev = s.value if hasattr(s, 'value') else str(s)
        if sev in severity_counts:
            severity_counts[sev] += 1

    unique_types_result = await db.execute(select(Finding.title).distinct())
    unique_vuln_types = [row[0] for row in unique_types_result.all()]

    unique_endpoints_result = await db.execute(select(Request.path).distinct().limit(1000))
    unique_endpoints = [row[0] for row in unique_endpoints_result.all() if row[0]]

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    proxy_requests_today_result = await db.execute(
        select(func.count(Request.id)).where(Request.timestamp >= today_start)
    )
    proxy_requests_today = proxy_requests_today_result.scalar() or 0

    from core.storage.database import AsyncSessionLocal
    active_pipelines = 0
    discovery_jobs_running = 0
    fuzz_jobs_running = 0

    try:
        from core.storage.models import ScanJob, ContentDiscoveryJob, FuzzJob
        async with AsyncSessionLocal() as stats_db:
            ap_result = await stats_db.execute(
                select(func.count(ScanJob.id)).where(ScanJob.status == "running")
            )
            active_pipelines = ap_result.scalar() or 0

            dj_result = await stats_db.execute(
                select(func.count(ContentDiscoveryJob.id)).where(ContentDiscoveryJob.status == "running")
            )
            discovery_jobs_running = dj_result.scalar() or 0

            fj_result = await stats_db.execute(
                select(func.count(FuzzJob.id)).where(FuzzJob.status == "running")
            )
            fuzz_jobs_running = fj_result.scalar() or 0
    except Exception:
        pass

    return {
        "total_findings": total_findings,
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "unique_vuln_types": unique_vuln_types,
        "unique_endpoints": unique_endpoints,
        "proxy_requests_today": proxy_requests_today,
        "active_pipelines": active_pipelines,
        "discovery_jobs_running": discovery_jobs_running,
        "fuzz_jobs_running": fuzz_jobs_running,
    }


@router.get("/findings/recent")
async def get_recent_findings(
    hours: int = Query(24, description="Lookback period in hours"),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.request))
        .where(Finding.created_at >= since)
        .order_by(Finding.created_at.desc())
        .limit(20)
    )
    findings = result.scalars().all()
    return [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value,
            "method": f.request.method if f.request else "",
            "url": f.request.url if f.request else "",
            "status": f.request.response_status if f.request else None,
            "created_at": f.created_at.isoformat() if f.created_at else "",
        }
        for f in findings
    ]
