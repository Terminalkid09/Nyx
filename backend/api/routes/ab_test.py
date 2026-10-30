"""Multi-identity replay API (IDOR / tenant-isolation check)."""
from __future__ import annotations

import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.deps import ensure_authorized
from core.authorization import authorize
from modules.ab_test.service import Identity, run_comparison

router = APIRouter(prefix="/api/ab-test", tags=["ab-test"])


class IdentityBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    headers: dict[str, str] = {}


class ABTestRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict[str, str] = {}
    body: str | None = None
    identity_a: IdentityBody
    identity_b: IdentityBody
    # The anonymous leg is what turns "both users see the same page" into
    # "nobody needs to log in at all".
    anonymous: bool = True
    session_id: str


@router.post("/run")
async def run(body: ABTestRequest) -> dict:
    parsed = urlparse(body.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise HTTPException(400, detail="url must be an absolute http(s) URL")

    try:
        session_id = uuid.UUID(body.session_id)
    except (TypeError, ValueError):
        raise HTTPException(400, detail="session_id is not a UUID")

    decision = await authorize(session_id, body.url, require_session=True)
    ensure_authorized(*decision)

    try:
        result = await run_comparison(
            request={
                "method": body.method.upper(),
                "url": body.url,
                "headers": body.headers,
                "body": body.body,
            },
            identity_a=Identity(name=body.identity_a.name, headers=body.identity_a.headers),
            identity_b=Identity(name=body.identity_b.name, headers=body.identity_b.headers),
            anonymous=body.anonymous,
        )
    except Exception as exc:  # noqa: BLE001 — surface a clean 502
        raise HTTPException(502, detail=f"Replay failed: {exc}") from exc
    return result.to_dict()
