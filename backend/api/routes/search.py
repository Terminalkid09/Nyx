from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func, cast, String
from api.deps import get_db
from core.storage.models import Request, Finding
import math

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
async def search(
    q: str = Query(..., min_length=1),
    type: str = Query("all", pattern="^(all|requests|responses|findings)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    like_pattern = f"%{q}%"
    type_q = type
    results = []
    total = 0

    if type_q in ("all", "requests"):
        stmt = select(Request).where(
            or_(
                Request.url.ilike(like_pattern),
                Request.request_body.ilike(like_pattern),
                Request.response_body.ilike(like_pattern),
                Request.method.ilike(like_pattern),
                Request.host.ilike(like_pattern),
                cast(Request.request_headers, String).ilike(like_pattern),
                cast(Request.response_headers, String).ilike(like_pattern),
            )
        ).order_by(Request.timestamp.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count_result = await db.execute(count_stmt)
        req_total = total_count_result.scalar() or 0
        total += req_total

        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)
        req_result = await db.execute(stmt)
        for r in req_result.scalars().all():
            snippet = _build_snippet(q, r)
            results.append({
                "type": "request",
                "id": str(r.id),
                "session_id": str(r.session_id),
                "method": r.method,
                "url": r.url,
                "host": r.host,
                "path": r.path,
                "status": r.response_status,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "snippet": snippet,
                "match_location": _find_match_location(q, r),
            })

    if type_q in ("all", "responses") and (type_q != "requests" or page == 1):
        stmt = select(Request).where(
            or_(
                Request.response_body.ilike(like_pattern),
                cast(Request.response_headers, String).ilike(like_pattern),
                cast(Request.response_status, String).ilike(like_pattern),
            )
        ).order_by(Request.timestamp.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count_result = await db.execute(count_stmt)
        resp_total = total_count_result.scalar() or 0
        total += resp_total

        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)
        resp_result = await db.execute(stmt)
        for r in resp_result.scalars().all():
            results.append({
                "type": "response",
                "id": str(r.id),
                "session_id": str(r.session_id),
                "method": r.method,
                "url": r.url,
                "status": r.response_status,
                "content_type": r.response_content_type,
                "size_bytes": r.response_size_bytes,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "snippet": _build_response_snippet(q, r),
                "match_location": "response_body" if r.response_body and q.lower() in r.response_body.lower() else "response_headers",
            })

    if type_q in ("all", "findings"):
        stmt = select(Finding).where(
            or_(
                Finding.title.ilike(like_pattern),
                Finding.description.ilike(like_pattern),
                Finding.evidence.ilike(like_pattern),
                Finding.module.ilike(like_pattern),
            )
        ).order_by(Finding.created_at.desc())

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_count_result = await db.execute(count_stmt)
        finding_total = total_count_result.scalar() or 0
        total += finding_total

        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)
        finding_result = await db.execute(stmt)
        for f in finding_result.scalars().all():
            snippet_ctx = _highlight_context(q, f.description or f.title)
            results.append({
                "type": "finding",
                "id": str(f.id),
                "session_id": str(f.session_id),
                "request_id": str(f.request_id) if f.request_id else None,
                "module": f.module,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "title": f.title,
                "description": f.description,
                "timestamp": f.created_at.isoformat() if f.created_at else None,
                "snippet": snippet_ctx,
                "match_location": _find_finding_match_location(q, f),
            })

    return {
        "results": results,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, math.ceil(total / page_size)),
    }


def _build_snippet(q: str, req: Request) -> str | None:
    candidates = []
    if req.url and q.lower() in req.url.lower():
        candidates.append(("URL", _highlight_context(q, req.url)))
    if req.request_body and q.lower() in req.request_body.lower():
        candidates.append(("Request Body", _highlight_context(q, req.request_body)))
    if req.response_body and q.lower() in req.response_body.lower():
        candidates.append(("Response Body", _highlight_context(q, req.response_body)))
    if req.host and q.lower() in req.host.lower():
        candidates.append(("Host", _highlight_context(q, req.host)))
    for _, snippet in candidates:
        if snippet:
            return snippet
    return None


def _build_response_snippet(q: str, req: Request) -> str | None:
    if req.response_body and q.lower() in req.response_body.lower():
        return _highlight_context(q, req.response_body)
    return None


def _highlight_context(q: str, text: str, context_chars: int = 80) -> str:
    idx = text.lower().find(q.lower())
    if idx == -1:
        return text[:context_chars * 2]
    start = max(0, idx - context_chars)
    end = min(len(text), idx + len(q) + context_chars)
    snippet = text[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet


def _find_match_location(q: str, req: Request) -> str:
    if req.url and q.lower() in req.url.lower():
        return "url"
    if req.request_body and q.lower() in req.request_body.lower():
        return "request_body"
    if req.response_body and q.lower() in req.response_body.lower():
        return "response_body"
    if req.host and q.lower() in req.host.lower():
        return "host"
    return "unknown"


def _find_finding_match_location(q: str, finding: Finding) -> str:
    if finding.title and q.lower() in finding.title.lower():
        return "title"
    if finding.description and q.lower() in finding.description.lower():
        return "description"
    if finding.evidence and q.lower() in finding.evidence.lower():
        return "evidence"
    return "unknown"
