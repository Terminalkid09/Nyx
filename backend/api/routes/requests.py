from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_db
from api.schemas.requests import RequestResponse, RequestListResponse
from core.storage.crud.requests import get_request, list_requests
import uuid

router = APIRouter(prefix="/api/requests", tags=["requests"])


@router.get("", response_model=RequestListResponse)
async def list_all_requests(
    session_id: uuid.UUID | None = Query(None),
    host: str | None = Query(None),
    method: str | None = Query(None),
    status: int | None = Query(None),
    search: str | None = Query(None),
    flagged: bool | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    items, total = await list_requests(
        db,
        session_id=session_id,
        host=host,
        method=method,
        status=status,
        search=search,
        flagged=flagged,
        page=page,
        per_page=per_page,
    )
    return RequestListResponse(
        items=[RequestResponse.model_validate(r) for r in items],
        total=total,
        page=page,
        per_page=per_page,
    )


def _har_headers(headers: dict | None) -> list[dict]:
    return [{"name": str(k), "value": str(v)} for k, v in (headers or {}).items()]


def _har_entry(r) -> dict:
    """Convert a stored Request row into a HAR 1.2 entry."""
    body = r.request_body if r.request_body is not None else (
        r.request_body_binary.decode("utf-8", errors="replace") if r.request_body_binary else ""
    )
    resp_body = r.response_body if r.response_body is not None else (
        r.response_body_binary.decode("utf-8", errors="replace") if r.response_body_binary else ""
    )
    status = r.response_status or 0
    started = r.timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "startedDateTime": started,
        "time": r.response_time_ms or 0,
        "request": {
            "method": r.method,
            "url": r.url,
            "httpVersion": r.http_version or "HTTP/1.1",
            "headers": _har_headers(r.request_headers),
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(body.encode("utf-8")) if body else 0,
            "postData": (
                {"mimeType": (r.request_headers or {}).get("Content-Type")
                 or (r.request_headers or {}).get("content-type") or "application/octet-stream",
                 "text": body}
                if body else None
            ),
        },
        "response": {
            "status": status,
            "statusText": r.response_reason or "",
            "httpVersion": r.http_version or "HTTP/1.1",
            "headers": _har_headers(r.response_headers),
            "cookies": [],
            "content": {
                "size": r.response_size_bytes if r.response_size_bytes is not None else len(resp_body.encode("utf-8")),
                "mimeType": r.response_content_type or "application/octet-stream",
                "text": resp_body,
                **({"encoding": "base64"} if (r.response_body is None and r.response_body_binary is not None) else {}),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": r.response_size_bytes or 0,
        },
        "cache": {},
        "timings": {"send": 0, "wait": r.response_time_ms or 0, "receive": 0},
    }


# NOTE: declared BEFORE /{request_id} so "export" is never parsed as a UUID.
@router.get("/export/har")
async def export_har(
    session_id: uuid.UUID | None = Query(None),
    limit: int = Query(5000, ge=1, le=50000),
    db: AsyncSession = Depends(get_db),
):
    """Export captured traffic as a HAR 1.2 archive.

    HAR opens directly in Chrome DevTools, Firefox, Charles and every HTTP
    inspection tool — the standard interchange format for recorded sessions.
    """
    items, _total = await list_requests(db, session_id=session_id, page=1, per_page=limit)
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "Nyx Web Security Testing Suite", "version": "1.0"},
            "entries": [_har_entry(r) for r in items],
        }
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"nyx-session-{stamp}.har"
    return JSONResponse(
        content=har,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{request_id}", response_model=RequestResponse)
async def get_request_by_id(request_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    req = await get_request(db, request_id)
    if not req:
        raise HTTPException(404, detail="Request not found")
    return RequestResponse.model_validate(req)
