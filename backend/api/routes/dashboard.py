from datetime import datetime, timezone, timedelta
import uuid

from fastapi import APIRouter, Depends, Request as FastAPIRequest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text

from api.deps import get_db
from core.storage.models import Finding, Request, ScanJob, FuzzJob

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    request: FastAPIRequest = None,
    session_id: uuid.UUID | None = None,
):
    now = datetime.now(timezone.utc)

    # Total findings
    total_findings_result = await db.execute(
        select(func.count(Finding.id)).where(
            Finding.session_id == session_id if session_id else text("1=1")
        )
    )
    total_findings = total_findings_result.scalar() or 0

    # Findings by severity
    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.session_id == session_id if session_id else text("1=1"))
        .group_by(Finding.severity)
    )
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in severity_result:
        findings_by_severity[row.severity.value if hasattr(row.severity, 'value') else row.severity] = row[1]

    # Finding trends (last 14 days) — single query
    trends_lookup: dict[str, dict[str, int]] = {}
    fourteen_days_ago = now - timedelta(days=13)
    trend_rows = await db.execute(
        select(
            func.date(Finding.created_at).label("day"),
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(Finding.created_at >= fourteen_days_ago)
        .where(Finding.session_id == session_id if session_id else text("1=1"))
        .group_by(func.date(Finding.created_at), Finding.severity)
        .order_by(func.date(Finding.created_at))
    )
    for row in trend_rows:
        day_str = str(row.day)
        if day_str not in trends_lookup:
            trends_lookup[day_str] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        sev = row.severity.value if hasattr(row.severity, 'value') else row.severity
        trends_lookup[day_str][sev] = row.cnt
    trends = []
    for i in range(13, -1, -1):
        day = now - timedelta(days=i)
        day_str = day.strftime("%Y-%m-%d")
        trends.append({"date": day_str, **(trends_lookup.get(day_str, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}))})

    # Top endpoints
    top_endpoints_result = await db.execute(
        select(Request.path, func.count(Finding.id).label("cnt"))
        .join(Finding, Finding.request_id == Request.id)
        .where(Finding.session_id == session_id if session_id else text("1=1"))
        .group_by(Request.path)
        .order_by(text("cnt DESC"))
        .limit(10)
    )
    top_endpoints = [
        {"path": row.path or "/unknown", "count": row.cnt}
        for row in top_endpoints_result
    ]

    # Vulnerability type breakdown
    vuln_result = await db.execute(
        select(Finding.title, func.count(Finding.id).label("cnt"))
        .where(Finding.session_id == session_id if session_id else text("1=1"))
        .group_by(Finding.title)
        .order_by(text("cnt DESC"))
        .limit(15)
    )
    vuln_breakdown = [
        {"type": row.title, "count": row.cnt}
        for row in vuln_result
    ]

    # Scan job history
    scan_result = await db.execute(
        select(ScanJob)
        .where(ScanJob.session_id == session_id if session_id else text("1=1"))
        .order_by(ScanJob.created_at.desc())
        .limit(20)
    )
    scan_history = [
        {
            "id": str(job.id),
            "target": job.target_url or "",
            "status": job.status or "unknown",
            "progress": job.progress or 0,
            "total_checks": job.total_checks or 0,
            "passed_checks": job.passed_checks or 0,
            "failed_checks": job.failed_checks or 0,
            "created_at": job.created_at.isoformat() if job.created_at else "",
        }
        for job in scan_result.scalars().all()
    ]

    # Active scans count
    active_scans_result = await db.execute(
        select(func.count(ScanJob.id))
        .where(ScanJob.status == "running")
        .where(ScanJob.session_id == session_id if session_id else text("1=1"))
    )
    active_scans = active_scans_result.scalar() or 0

    # Active fuzz jobs
    active_fuzz_result = await db.execute(
        select(func.count(FuzzJob.id))
        .where(FuzzJob.status.in_(["pending", "running"]))
        .where(FuzzJob.session_id == session_id if session_id else text("1=1"))
    )
    active_fuzz_jobs = active_fuzz_result.scalar() or 0

    # Recommendations count
    recs_count = 0
    if request and hasattr(request.app.state, "recommender_engine") and request.app.state.recommender_engine:
        try:
            recs_count = request.app.state.recommender_engine.get_stats().get("total", 0)
        except Exception:
            pass

    # Active pipelines count
    pipelines_count = 0
    if request and hasattr(request.app.state, "pipeline_service") and request.app.state.pipeline_service:
        try:
            pipelines = request.app.state.pipeline_service.list_pipelines()
            pipelines_count = len([p for p in pipelines if p.get("status") == "running"])
        except Exception:
            pass

    # Proxy requests today
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    proxy_result = await db.execute(
        select(func.count(Request.id))
        .where(Request.timestamp >= today_start)
        .where(Request.session_id == session_id if session_id else text("1=1"))
    )
    proxy_requests_today = proxy_result.scalar() or 0

    # Total endpoints
    endpoints_result = await db.execute(
        select(func.count(func.distinct(Request.path)))
        .where(Request.session_id == session_id if session_id else text("1=1"))
    )
    total_endpoints = endpoints_result.scalar() or 0

    # Recent findings with endpoint info
    try:
        from sqlalchemy.orm import selectinload
        recent_result = await db.execute(
            select(Finding).options(
                selectinload(Finding.request)
            )
            .where(Finding.session_id == session_id if session_id else text("1=1"))
            .order_by(Finding.created_at.desc())
            .limit(15)
        )
        recent_findings = []
        for f in recent_result.scalars().all():
            recent_findings.append({
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
                "endpoint": f.request.path if f.request else "/unknown",
                "module": f.module,
                "created_at": f.created_at.isoformat() if f.created_at else "",
            })
    except Exception:
        recent_findings = []

    return {
        "total_findings": total_findings,
        "findings_by_severity": findings_by_severity,
        "trends": trends,
        "top_endpoints": top_endpoints,
        "vuln_breakdown": vuln_breakdown,
        "scan_history": scan_history,
        "active_scans": active_scans,
        "active_fuzz_jobs": active_fuzz_jobs,
        "active_pipelines": pipelines_count,
        "recommendations": recs_count,
        "proxy_requests_today": proxy_requests_today,
        "total_endpoints": total_endpoints,
        "recent_findings": recent_findings,
    }
