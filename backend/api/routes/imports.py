"""Import endpoint inventories from external API descriptions.

The import itself sends no traffic, so it is not gated by the authorization
engine. Applying the declared servers to a session scope is a separate,
explicit opt-in: it writes ``include`` rules that every later probe honours.
"""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from core.storage.models import Session, TargetScopeRule
from modules.importer.openapi import (
    MAX_DOCUMENT_BYTES,
    OpenAPIImportError,
    inventory,
    parse_document,
    server_hosts,
)

router = APIRouter(prefix="/api/import", tags=["import"])


class OpenAPIImportRequest(BaseModel):
    # The document is the payload: JSON or YAML, as text.
    document: str = Field(min_length=2, max_length=MAX_DOCUMENT_BYTES)
    filename: str | None = None
    session_id: uuid.UUID | None = None
    apply_scope: bool = False


async def _apply_scope(db: AsyncSession, session_id: uuid.UUID, servers: tuple[str, ...]) -> dict:
    if await db.get(Session, session_id) is None:
        raise HTTPException(404, detail="Session not found")

    existing = (
        await db.execute(select(TargetScopeRule).where(TargetScopeRule.session_id == session_id))
    ).scalars().all()
    seen = {(rule.rule_type, rule.pattern) for rule in existing}
    order = max((rule.order for rule in existing), default=-1) + 1

    added: list[str] = []
    skipped: list[str] = []
    for host in server_hosts(servers):
        if ("include", host) in seen:
            skipped.append(host)
            continue
        db.add(
            TargetScopeRule(
                session_id=session_id,
                name=f"OpenAPI: {host}",
                rule_type="include",
                pattern=host,
                is_regex=False,
                match_domain=True,
                protocols=[],
                order=order,
            )
        )
        order += 1
        seen.add(("include", host))
        added.append(host)

    if added:
        await db.commit()
    return {"added": added, "skipped": skipped}


@router.post("/openapi")
async def import_openapi(
    body: OpenAPIImportRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        document = parse_document(body.document)
    except OpenAPIImportError as exc:
        raise HTTPException(400, detail=str(exc))

    result = inventory(document)
    if body.filename:
        result["filename"] = Path(body.filename).name
    if body.apply_scope:
        if body.session_id is None:
            raise HTTPException(
                400, detail="session_id is required when apply_scope is true"
            )
        result["scope"] = await _apply_scope(db, body.session_id, document.servers)
    return result
