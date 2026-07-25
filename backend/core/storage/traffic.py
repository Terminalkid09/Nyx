"""Persist proxy events as durable request history."""
import uuid

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import Request, Session

DEFAULT_SESSION_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


class TrafficStorageService:
    def __init__(self, event_bus: EventBus, max_body_size: int):
        self.max_body_size = max_body_size
        self._event_bus = event_bus
        event_bus.subscribe("request.captured", self._on_request)
        event_bus.subscribe("response.received", self._on_response)

    def stop(self):
        self._event_bus.unsubscribe("request.captured", self._on_request)
        self._event_bus.unsubscribe("response.received", self._on_response)

    def _body(self, value):
        if value is None:
            return None, False
        return value[:self.max_body_size], len(value.encode("utf-8", errors="replace")) > self.max_body_size

    @staticmethod
    def _uuid(value, fallback):
        try:
            return uuid.UUID(str(value))
        except (TypeError, ValueError):
            return fallback

    async def _on_request(self, event: dict):
        request_id = self._uuid(event.get("request_id"), None)
        if not request_id:
            return
        body, truncated = self._body(event.get("request_body"))
        async with AsyncSessionLocal() as db:
            if await db.get(Request, request_id):
                return
            db.add(Request(id=request_id, session_id=self._uuid(event.get("session_id"), DEFAULT_SESSION_ID), method=event.get("method", "GET")[:16], url=event.get("url", ""), host=event.get("host", "")[:512], path=event.get("path", ""), request_headers=event.get("request_headers") or {}, request_body=body, is_body_truncated=truncated))
            await db.commit()

    async def _on_response(self, event: dict):
        request_id = self._uuid(event.get("request_id"), None)
        if not request_id:
            return
        body, truncated = self._body(event.get("body"))
        async with AsyncSessionLocal() as db:
            request = await db.get(Request, request_id)
            if not request:
                request = Request(id=request_id, session_id=self._uuid(event.get("session_id"), DEFAULT_SESSION_ID), method=event.get("method", "GET")[:16], url=event.get("url", ""), host=event.get("host", "")[:512], path=event.get("path", ""), request_headers=event.get("request_headers") or {}, request_body=event.get("request_body"))
                db.add(request)
            request.response_status = event.get("status")
            request.response_headers = event.get("headers") or {}
            request.response_body = body
            request.response_content_type = event.get("content_type")
            request.response_size_bytes = event.get("size_bytes")
            request.response_time_ms = event.get("response_time_ms")
            request.is_body_truncated = request.is_body_truncated or truncated
            await db.commit()


async def ensure_default_session():
    async with AsyncSessionLocal() as db:
        if not await db.get(Session, DEFAULT_SESSION_ID):
            db.add(Session(id=DEFAULT_SESSION_ID, name="Default Session"))
            await db.commit()
