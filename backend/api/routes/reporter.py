from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from api.deps import get_db
from core.storage.models import Finding, Request
from reporter.service import ReporterService
import uuid

router = APIRouter(prefix="/api/reports", tags=["reporter"])


@router.post("/generate")
async def generate_report(
    session_id: uuid.UUID,
    format: str = Query("html", pattern="^(html|pdf|json|md)$"),
    target_url: str | None = Query(None, description="Optional target domain/URL for the report"),
    db: AsyncSession = Depends(get_db),
):
    findings_result = await db.execute(
        select(Finding).where(Finding.session_id == session_id)
    )
    findings = list(findings_result.scalars().all())

    request_count_result = await db.execute(
        select(func.count(Request.id)).where(Request.session_id == session_id)
    )
    request_count = request_count_result.scalar() or 0

    findings_dicts = [
        {
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cwe": f.cwe,
            "module": f.module,
            "cvss_score": f.cvss_score,
            "cvss_vector": f.cvss_vector,
        }
        for f in findings
    ]

    reporter = ReporterService()
    try:
        report_bytes = await reporter.generate(
            session_id=session_id,
            findings=findings_dicts,
            request_count=request_count,
            format=format,
            target_url=target_url,
        )
    except ValueError as e:
        raise HTTPException(400, detail=str(e))

    media_type = {
        "html": "text/html",
        "pdf": "application/pdf",
        "json": "application/json",
        "md": "text/markdown",
    }.get(format, "text/plain")

    from fastapi.responses import Response
    return Response(content=report_bytes, media_type=media_type)
