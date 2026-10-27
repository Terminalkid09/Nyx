import uuid
from datetime import datetime, timezone, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from api.deps import get_db
from core.authorization import authorize
from core.storage.models import Finding, Request

router = APIRouter(prefix="/api/triage", tags=["triage"])

TriageStatus = Literal["open", "confirmed", "needs_review", "fixed", "false_positive"]
SEVERITIES = ("critical", "high", "medium", "low", "info")
# Dismissed and fixed findings are history: they stay in the database (the
# evidence is still useful) but out of the working list by default.
CLOSED_STATUSES = ("false_positive", "fixed")


def _effective_severity(f: Finding) -> str:
    """Operator override wins over what the scanner decided."""
    if f.severity_override in SEVERITIES:
        return f.severity_override
    return f.severity.value if hasattr(f.severity, "value") else str(f.severity)


class FindingUpdate(BaseModel):
    triage_status: TriageStatus | None = None
    # ``None`` clears the override, a severity sets it.
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    clear_severity_override: bool = False


async def authorize_finding_target(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    """Retest re-sends a real request, so it must honour scope and RoE.

    Without this the operator could probe a target the engagement no longer
    covers just by pressing retest on an old finding.
    """
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, detail="Finding not found")
    req = await db.get(Request, finding.request_id)
    if not req or not req.url:
        raise HTTPException(400, detail="Associated request not found")

    allowed, kind, detail = await authorize(finding.session_id, req.url)
    if not allowed:
        raise HTTPException(403, detail=f"Target not authorized ({kind}: {detail})")


@router.get("/findings/grouped")
async def get_grouped_findings(
    session_id: uuid.UUID = Query(..., description="Session to scope findings to"),
    include_triaged: bool = Query(False, description="Also return dismissed/fixed findings"),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Finding)
        .where(Finding.session_id == session_id)
        .options(selectinload(Finding.request))
        .order_by(Finding.created_at.desc())
    )
    if not include_triaged:
        query = query.where(Finding.triage_status.notin_(CLOSED_STATUSES))
    result = await db.execute(query)
    findings = result.scalars().all()

    severity_order = {sev: index for index, sev in enumerate(SEVERITIES)}
    groups: dict[str, dict] = {}
    for f in findings:
        path = f.request.path if f.request else "/unknown"
        key = f"{f.title}@{path}"
        if key not in groups:
            groups[key] = {
                "key": key,
                "title": f.title,
                "severity": _effective_severity(f),
                "severity_override": f.severity_override,
                "triage_status": f.triage_status,
                "finding_ids": [],
                "count": 0,
                "endpoint": path,
                "host": (f.request.host or "") if f.request else "",
                "method": (f.request.method or "GET") if f.request else "GET",
                "url": (f.request.url or "") if f.request else "",
                "request_headers": (f.request.request_headers or {}) if f.request else {},
                "request_body": (f.request.request_body or "") if f.request else "",
                "request_id": str(f.request_id) if f.request_id else "",
                "request_session_id": str(f.request.session_id) if f.request and f.request.session_id else "",
                "vuln_type": f.title,
                "evidence_preview": (f.evidence or "")[:200],
                "first_seen": f.created_at.isoformat() if f.created_at else "",
                "last_seen": f.created_at.isoformat() if f.created_at else "",
            }
        g = groups[key]
        g["count"] += 1
        g["finding_ids"].append(str(f.id))
        # A group inherits the worst effective severity of its members, so an
        # override on one instance cannot hide the others.
        if severity_order.get(_effective_severity(f), 99) < severity_order.get(g["severity"], 99):
            g["severity"] = _effective_severity(f)
        if f.severity_override and not g["severity_override"]:
            g["severity_override"] = f.severity_override
        if f.request and f.request.request_body and not g["request_body"]:
            g["request_body"] = f.request.request_body
            g["method"] = f.request.method or g["method"]
            g["url"] = f.request.url or g["url"]
            g["request_headers"] = f.request.request_headers or {}
        if f.evidence and not g["evidence_preview"]:
            g["evidence_preview"] = f.evidence[:200]
        seen = f.created_at.isoformat() if f.created_at else ""
        if seen < g["first_seen"]:
            g["first_seen"] = seen
        if seen > g["last_seen"]:
            g["last_seen"] = seen

    sorted_groups = sorted(groups.values(), key=lambda g: severity_order.get(g["severity"], 99))
    return {"groups": sorted_groups}


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: uuid.UUID,
    body: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Record a triage decision (dismiss, confirm, re-rate) without losing it."""
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, detail="Finding not found")

    if body.clear_severity_override:
        finding.severity_override = None
    elif body.severity is not None:
        finding.severity_override = body.severity
    if body.triage_status is not None:
        finding.triage_status = body.triage_status

    await db.commit()
    await db.refresh(finding)
    return {
        "id": str(finding.id),
        "triage_status": finding.triage_status,
        "severity": _effective_severity(finding),
        "severity_override": finding.severity_override,
    }


@router.get("/findings/{finding_id}/retest")
async def retest_finding(
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _authorized: None = Depends(authorize_finding_target),
):
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

            # A different status is a signal, not proof: a WAF, a rate limit or
            # a rotated token also change it. Only a response that still looks
            # like the original confirms the finding; anything else goes back
            # to the operator instead of being marked "fixed" on a guess.
            if req.response_status and resp.status_code == req.response_status:
                result = "confirmed"
            else:
                result = "needs_review"
            finding.triage_status = result
            await db.commit()

            return {
                "result": result,
                "evidence": evidence,
                "status_code": resp.status_code,
                "triage_status": finding.triage_status,
            }
    except Exception as e:
        return {"result": "error", "evidence": str(e), "triage_status": finding.triage_status}


@router.get("/stats")
async def get_stats(
    session_id: uuid.UUID = Query(..., description="Session to scope stats to"),
    db: AsyncSession = Depends(get_db),
):
    total_findings_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.session_id == session_id)
    )
    total_findings = total_findings_result.scalar() or 0

    all_sev_result = await db.execute(
        select(Finding.severity).where(Finding.session_id == session_id)
    )
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in all_sev_result.all():
        s = row[0]
        sev = s.value if hasattr(s, 'value') else str(s)
        if sev in severity_counts:
            severity_counts[sev] += 1

    unique_types_result = await db.execute(
        select(Finding.title).distinct().where(Finding.session_id == session_id)
    )
    unique_vuln_types = [row[0] for row in unique_types_result.all()]

    unique_endpoints_result = await db.execute(
        select(Request.path).distinct().where(Request.session_id == session_id).limit(1000)
    )
    unique_endpoints = [row[0] for row in unique_endpoints_result.all() if row[0]]

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    proxy_requests_today_result = await db.execute(
        select(func.count(Request.id)).where(
            Request.session_id == session_id,
            Request.timestamp >= today_start,
        )
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
    session_id: uuid.UUID = Query(..., description="Session to scope findings to"),
    hours: int = Query(24, description="Lookback period in hours"),
    db: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(Finding)
        .options(selectinload(Finding.request))
        .where(Finding.session_id == session_id, Finding.created_at >= since)
        .order_by(Finding.created_at.desc())
        .limit(20)
    )
    findings = result.scalars().all()
    return [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": _effective_severity(f),
            "triage_status": f.triage_status,
            "method": f.request.method if f.request else "",
            "url": f.request.url if f.request else "",
            "status": f.request.response_status if f.request else None,
            "created_at": f.created_at.isoformat() if f.created_at else "",
        }
        for f in findings
    ]
