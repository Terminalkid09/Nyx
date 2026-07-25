import io
import csv
import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_db
from core.storage.models import Session, Request, Finding, MatchReplaceRule, InterceptorRule, SessionHandlingRule, CookieJar

router = APIRouter(prefix="/api", tags=["backup"])


@router.get("/backup")
async def full_backup(db: AsyncSession = Depends(get_db)):
    sessions_result = await db.execute(select(Session))
    sessions = sessions_result.scalars().all()

    requests_result = await db.execute(select(Request).order_by(Request.timestamp))
    all_requests = requests_result.scalars().all()

    findings_result = await db.execute(select(Finding))
    all_findings = findings_result.scalars().all()

    rules_data = {}
    for model_cls, key in [
        (MatchReplaceRule, "match_replace_rules"),
        (InterceptorRule, "interceptor_rules"),
        (SessionHandlingRule, "session_handling_rules"),
        (CookieJar, "cookie_jar"),
    ]:
        r = await db.execute(select(model_cls))
        items = []
        for item in r.scalars().all():
            d = {c.name: getattr(item, c.name) for c in item.__table__.columns}
            for col in ("id", "session_id", "created_at", "updated_at"):
                val = d.get(col)
                if isinstance(val, uuid.UUID):
                    d[col] = str(val)
                elif isinstance(val, datetime):
                    d[col] = val.isoformat() if val else None
            items.append(d)
        rules_data[key] = items

    backup = {
        "nyx_version": "1.0.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "stats": {
            "sessions": len(sessions),
            "requests": len(all_requests),
            "findings": len(all_findings),
            "match_replace_rules": len(rules_data["match_replace_rules"]),
            "interceptor_rules": len(rules_data["interceptor_rules"]),
            "session_handling_rules": len(rules_data["session_handling_rules"]),
            "cookie_jar": len(rules_data["cookie_jar"]),
        },
        "data": {
            "sessions": [
                {
                    "id": str(s.id),
                    "name": s.name,
                    "scope": s.scope,
                    "notes": s.notes,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
                for s in sessions
            ],
            "requests": [
                {
                    "id": str(r.id),
                    "session_id": str(r.session_id),
                    "method": r.method,
                    "url": r.url,
                    "host": r.host,
                    "path": r.path,
                    "request_headers": r.request_headers,
                    "request_body": r.request_body,
                    "response_status": r.response_status,
                    "response_reason": r.response_reason,
                    "response_headers": r.response_headers,
                    "response_body": r.response_body,
                    "response_time_ms": r.response_time_ms,
                    "is_flagged": r.is_flagged,
                    "tags": r.tags,
                    "notes": r.notes,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                }
                for r in all_requests
            ],
            "findings": [
                {
                    "id": str(f.id),
                    "session_id": str(f.session_id),
                    "request_id": str(f.request_id) if f.request_id else None,
                    "module": f.module,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cwe": f.cwe,
                    "cvss_score": f.cvss_score,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in all_findings
            ],
            **rules_data,
        },
    }

    return Response(
        content=json.dumps(backup, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="nyx_backup_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.json"'},
    )


@router.post("/export/findings")
async def export_findings(
    session_id: uuid.UUID | None = Query(None),
    severity: str | None = Query(None),
    module: str | None = Query(None),
    format: str = Query("json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
):
    query = select(Finding)
    if session_id:
        query = query.where(Finding.session_id == session_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if module:
        query = query.where(Finding.module == module)
    query = query.order_by(Finding.severity.desc(), Finding.created_at.desc())

    result = await db.execute(query)
    findings = result.scalars().all()

    rows = [
        {
            "id": str(f.id),
            "session_id": str(f.session_id),
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "module": f.module,
            "cwe": f.cwe,
            "cvss_score": f.cvss_score,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]

    if format == "json":
        return rows

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys() if rows else [])
    writer.writeheader()
    writer.writerows(rows)

    return StreamingResponse(
        iter([output.getvalue().encode("utf-8-sig")]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="findings_export_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv"'},
    )


@router.get("/stats")
async def db_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func

    session_count = (await db.execute(select(func.count(Session.id)))).scalar() or 0
    request_count = (await db.execute(select(func.count(Request.id)))).scalar() or 0
    finding_count = (await db.execute(select(func.count(Finding.id)))).scalar() or 0

    severity_result = await db.execute(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    )
    by_severity = {row[0].value if hasattr(row[0], "value") else str(row[0]): row[1] for row in severity_result.all()}

    return {
        "sessions": session_count,
        "requests": request_count,
        "findings": finding_count,
        "by_severity": by_severity,
    }
