"""F-03: attack path graph for a session."""
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from core.storage.models import Finding, Request
from modules.attack_path.graph import build_graph

router = APIRouter(prefix="/api/attack-path", tags=["attack-path"])


@router.get("/{session_id}")
async def get_attack_path(session_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    rows = (
        await db.execute(
            select(Finding, Request.url)
            .outerjoin(Request, Finding.request_id == Request.id)
            .where(Finding.session_id == session_id)
        )
    ).all()

    findings = [
        {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
            "cwe": finding.cwe,
            "request_id": str(finding.request_id) if finding.request_id else None,
            "url": url,
        }
        for finding, url in rows
    ]
    return build_graph(findings).to_dict()
