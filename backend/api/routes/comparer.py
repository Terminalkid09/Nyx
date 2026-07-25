import difflib
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from api.deps import get_db
from core.storage.models import ComparerItem, Request

router = APIRouter(prefix="/api/comparer", tags=["comparer"])


class ComparerCreate(BaseModel):
    session_id: uuid.UUID
    left_request_id: uuid.UUID | None = None
    right_request_id: uuid.UUID | None = None
    left_type: str = "request"
    right_type: str = "request"
    left_content: str | None = None
    right_content: str | None = None
    left_label: str | None = None
    right_label: str | None = None
    notes: str | None = None


class ComparerResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    left_request_id: uuid.UUID | None
    right_request_id: uuid.UUID | None
    left_type: str
    right_type: str
    left_content: str | None
    right_content: str | None
    left_label: str | None
    right_label: str | None
    created_at: str
    notes: str | None

    model_config = {"from_attributes": True}


class DiffResult(BaseModel):
    left_label: str | None = None
    right_label: str | None = None
    method_diff: list[dict] | None = None
    url_diff: list[dict] | None = None
    status_diff: list[dict] | None = None
    headers_diff: list[dict] | None = None
    body_diff: list[dict] | None = None


def _compute_text_diff(text_a: str, text_b: str) -> list[dict]:
    lines_a = text_a.splitlines(keepends=True)
    lines_b = text_b.splitlines(keepends=True)
    result = []
    for line in difflib.unified_diff(lines_a, lines_b, n=3):
        line = line.rstrip("\n")
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("@@"):
            result.append({"type": "position", "value": line})
        elif line.startswith("-"):
            result.append({"type": "removed", "value": line[1:]})
        elif line.startswith("+"):
            result.append({"type": "added", "value": line[1:]})
        else:
            result.append({"type": "unchanged", "value": line[1:] if line.startswith(" ") else line})
    return result


def _compute_headers_diff(h_a: dict, h_b: dict) -> list[dict]:
    all_keys = set(list(h_a.keys()) + list(h_b.keys()))
    result = []
    for k in sorted(all_keys):
        va = h_a.get(k)
        vb = h_b.get(k)
        if va == vb:
            result.append({"type": "unchanged", "key": k, "value": va})
        elif va is None:
            result.append({"type": "added", "key": k, "value": vb})
        elif vb is None:
            result.append({"type": "removed", "key": k, "value": va})
        else:
            result.append({"type": "changed", "key": k, "left": va, "right": vb})
    return result


@router.get("/items", response_model=list[ComparerResponse])
async def list_items(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ComparerItem).order_by(ComparerItem.created_at.desc()))
    items = []
    for item in result.scalars().all():
        d = {
            "id": item.id,
            "session_id": item.session_id,
            "left_request_id": item.left_request_id,
            "right_request_id": item.right_request_id,
            "left_type": item.left_type,
            "right_type": item.right_type,
            "left_content": item.left_content,
            "right_content": item.right_content,
            "left_label": item.left_label,
            "right_label": item.right_label,
            "created_at": item.created_at.isoformat() if item.created_at else "",
            "notes": item.notes,
        }
        items.append(d)
    return items


@router.post("/items", response_model=ComparerResponse, status_code=201)
async def create_item(body: ComparerCreate, db: AsyncSession = Depends(get_db)):
    item = ComparerItem(
        session_id=body.session_id,
        left_request_id=body.left_request_id,
        right_request_id=body.right_request_id,
        left_type=body.left_type,
        right_type=body.right_type,
        left_content=body.left_content,
        right_content=body.right_content,
        left_label=body.left_label,
        right_label=body.right_label,
        notes=body.notes,
    )

    if body.left_request_id and not body.left_content:
        req = await db.get(Request, body.left_request_id)
        if req:
            item.left_content = req.request_body or req.response_body or ""
            item.left_label = item.left_label or f"{req.method} {req.url}"

    if body.right_request_id and not body.right_content:
        req = await db.get(Request, body.right_request_id)
        if req:
            item.right_content = req.request_body or req.response_body or ""
            item.right_label = item.right_label or f"{req.method} {req.url}"

    db.add(item)
    await db.commit()
    await db.refresh(item)
    return {
        "id": item.id,
        "session_id": item.session_id,
        "left_request_id": item.left_request_id,
        "right_request_id": item.right_request_id,
        "left_type": item.left_type,
        "right_type": item.right_type,
        "left_content": item.left_content,
        "right_content": item.right_content,
        "left_label": item.left_label,
        "right_label": item.right_label,
        "created_at": item.created_at.isoformat() if item.created_at else "",
        "notes": item.notes,
    }


@router.delete("/items/{item_id}", status_code=204)
async def delete_item(item_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    item = await db.get(ComparerItem, item_id)
    if not item:
        raise HTTPException(404, detail="Comparer item not found")
    await db.delete(item)
    await db.commit()


@router.get("/compare/{item_id}")
async def compare_item(item_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    item = await db.get(ComparerItem, item_id)
    if not item:
        raise HTTPException(404, detail="Comparer item not found")

    left_data: dict = {}
    right_data: dict = {}

    if item.left_request_id:
        req = await db.get(Request, item.left_request_id)
        if req:
            left_data = {
                "method": req.method,
                "url": req.url,
                "headers": req.request_headers or {},
                "body": req.request_body or "",
                "status": req.response_status,
                "response_headers": req.response_headers or {},
                "response_body": req.response_body or "",
            }

    if item.right_request_id:
        req = await db.get(Request, item.right_request_id)
        if req:
            right_data = {
                "method": req.method,
                "url": req.url,
                "headers": req.request_headers or {},
                "body": req.request_body or "",
                "status": req.response_status,
                "response_headers": req.response_headers or {},
                "response_body": req.response_body or "",
            }

    if item.left_content:
        left_data["body"] = item.left_content
    if item.right_content:
        right_data["body"] = item.right_content

    result = {
        "left_label": item.left_label,
        "right_label": item.right_label,
    }

    if "method" in left_data and "method" in right_data:
        if left_data["method"] != right_data["method"]:
            result["method_diff"] = [
                {"type": "removed", "value": left_data["method"]},
                {"type": "added", "value": right_data["method"]},
            ]

    if "url" in left_data and "url" in right_data:
        if left_data["url"] != right_data["url"]:
            result["url_diff"] = _compute_text_diff(left_data["url"], right_data["url"])

    if "status" in left_data and "status" in right_data:
        if left_data["status"] != right_data["status"]:
            result["status_diff"] = [
                {"type": "removed", "value": str(left_data["status"])},
                {"type": "added", "value": str(right_data["status"])},
            ]

    if "headers" in left_data and "headers" in right_data:
        result["headers_diff"] = _compute_headers_diff(left_data["headers"], right_data["headers"])

    if "body" in left_data and "body" in right_data:
        result["body_diff"] = _compute_text_diff(
            left_data.get("body", "") or "",
            right_data.get("body", "") or "",
        )

    return result
