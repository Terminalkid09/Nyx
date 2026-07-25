import json
import uuid
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel

from api.deps import get_db
from core.storage.models import WebSocketMessage
from core.storage.database import AsyncSessionLocal

router = APIRouter(prefix="/api/ws", tags=["websocket"])

logger = logging.getLogger(__name__)


class WSMessageResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    request_id: uuid.UUID
    direction: str
    timestamp: str
    payload: str | None
    is_binary: bool
    payload_size: int

    model_config = {"from_attributes": True}


@router.get("/messages", response_model=list[WSMessageResponse])
async def list_messages(
    session_id: uuid.UUID | None = Query(None),
    request_id: uuid.UUID | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(WebSocketMessage).order_by(WebSocketMessage.timestamp.asc())
    if session_id:
        stmt = stmt.where(WebSocketMessage.session_id == session_id)
    if request_id:
        stmt = stmt.where(WebSocketMessage.request_id == request_id)
    result = await db.execute(stmt)
    items = []
    for m in result.scalars().all():
        items.append({
            "id": m.id,
            "session_id": m.session_id,
            "request_id": m.request_id,
            "direction": m.direction,
            "timestamp": m.timestamp.isoformat() if m.timestamp else "",
            "payload": m.payload,
            "is_binary": m.is_binary,
            "payload_size": m.payload_size,
        })
    return items


@router.delete("/messages/{msg_id}", status_code=204)
async def delete_message(msg_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(WebSocketMessage).where(WebSocketMessage.id == msg_id))
    msg = result.scalar_one_or_none()
    if not msg:
        raise HTTPException(404, detail="WebSocket message not found")
    await db.delete(msg)
    await db.commit()


# --- Real-time WS interception endpoint ---

active_intercept_connections: list[WebSocket] = []


@router.websocket("/intercept")
async def ws_intercept(ws: WebSocket):
    await ws.accept()
    active_intercept_connections.append(ws)
    logger.info("WebSocket intercept client connected")
    try:
        while True:
            data = await ws.receive_text()
            try:
                msg = json.loads(data)
                msg_type = msg.get("type", "")

                if msg_type == "intercept":
                    await _handle_intercept_action(msg)
                elif msg_type == "forward":
                    await _handle_forward_action(msg)
                elif msg_type == "drop":
                    await _handle_drop_action(msg)
                else:
                    await ws.send_json({"type": "error", "message": f"Unknown message type: {msg_type}"})

            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "message": "Invalid JSON"})

    except WebSocketDisconnect:
        pass
    finally:
        if ws in active_intercept_connections:
            active_intercept_connections.remove(ws)


async def _handle_intercept_action(msg: dict):
    payload = msg.get("payload", "")
    is_binary = msg.get("is_binary", False)
    session_id = msg.get("session_id")
    request_id = msg.get("request_id")

    async with AsyncSessionLocal() as db:
        try:
            parsed_session_id = uuid.UUID(session_id) if session_id else uuid.uuid4()
        except (ValueError, AttributeError):
            parsed_session_id = uuid.uuid4()
        try:
            parsed_request_id = uuid.UUID(request_id) if request_id else uuid.uuid4()
        except (ValueError, AttributeError):
            parsed_request_id = uuid.uuid4()
        ws_msg = WebSocketMessage(
            session_id=parsed_session_id,
            request_id=parsed_request_id,
            direction="intercepted",
            payload=payload,
            is_binary=is_binary,
            payload_size=len(payload),
        )
        db.add(ws_msg)
        await db.commit()

    for conn in active_intercept_connections:
        try:
            await conn.send_json({
                "type": "intercepted",
                "payload": payload,
                "is_binary": is_binary,
            })
        except Exception:
            pass


async def _handle_forward_action(msg: dict):
    msg_id = msg.get("msg_id")
    modifications = msg.get("modifications", {})
    for conn in active_intercept_connections:
        try:
            await conn.send_json({
                "type": "forwarded",
                "msg_id": msg_id,
                "modifications": modifications,
            })
        except Exception:
            pass


async def _handle_drop_action(msg: dict):
    msg_id = msg.get("msg_id")
    for conn in active_intercept_connections:
        try:
            await conn.send_json({
                "type": "dropped",
                "msg_id": msg_id,
            })
        except Exception:
            pass


async def broadcast_ws_message(msg_data: dict):
    """Called by proxy addon to broadcast intercepted WS messages to connected clients."""
    for conn in active_intercept_connections:
        try:
            await conn.send_json(msg_data)
        except Exception:
            pass
