from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text

from api.deps import get_db
from core.storage.models import Finding, Request, ScanJob

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)

    # Total findings
    total_findings_result = await db.execute(select(func.count(Finding.id)))
    total_findings = total_findings_result.scalar() or 0

    # Findings by severity
    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
    )
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in severity_result:
        findings_by_severity[row.severity.value if hasattr(row.severity, 'value') else row.severity] = row[1]

    # Finding trends (last 14 days)
    trends = []
    for i in range(13, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_result = await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.created_at >= day_start)
            .where(Finding.created_at < day_end)
            .group_by(Finding.severity)
        )
        day_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for row in day_result:
            sev = row.severity.value if hasattr(row.severity, 'value') else row.severity
            day_counts[sev] = row[1]
        trends.append({
            "date": day_start.strftime("%Y-%m-%d"),
            **day_counts,
        })

    # Top endpoints
    top_endpoints_result = await db.execute(
        select(Request.path, func.count(Finding.id).label("cnt"))
        .join(Finding, Finding.request_id == Request.id)
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
    )
    active_scans = active_scans_result.scalar() or 0

    # Proxy requests today
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    proxy_result = await db.execute(
        select(func.count(Request.id))
        .where(Request.timestamp >= today_start)
    )
    proxy_requests_today = proxy_result.scalar() or 0

    # Total endpoints
    endpoints_result = await db.execute(
        select(func.count(func.distinct(Request.path)))
    )
    total_endpoints = endpoints_result.scalar() or 0

    # Recent findings with endpoint info
    try:
        from sqlalchemy.orm import selectinload
        recent_result = await db.execute(
            select(Finding).options(
                selectinload(Finding.request)
            )
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
        "proxy_requests_today": proxy_requests_today,
        "total_endpoints": total_endpoints,
        "recent_findings": recent_findings,
    }
