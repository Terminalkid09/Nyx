"""Persist proxy events as durable request history."""
import asyncio
import logging
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import delete, select, func
from sqlalchemy.exc import IntegrityError

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import Request, Session
from core.config import settings

DEFAULT_SESSION_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
# Dedicated session for MITM-captured traffic. MITM start stamps the proxy
# with this fixed ID and the frontend switches the active session to it, so
# intercepted traffic is always visible in the Proxy tab — independent of
# whatever session the user last had persisted in the UI (the source of the
# "MITM traffic never appears" bug: UI on Test_session, proxy stamping
# Default Session).
MITM_SESSION_ID = uuid.UUID("11111111-1111-1111-1111-111111111111")
logger = logging.getLogger(__name__)


class TrafficStorageService:
    def __init__(self, event_bus: EventBus, max_body_size: int):
        self.max_body_size = max_body_size
        self._event_bus = event_bus
        self._janitor_task: asyncio.Task | None = None
        event_bus.subscribe("request.captured", self._on_request)
        event_bus.subscribe("response.received", self._on_response)
        self._start_janitor()

    def _start_janitor(self):
        max_req = settings.MAX_STORED_REQUESTS
        max_hours = settings.REQUEST_RETENTION_HOURS
        if max_req <= 0 and max_hours <= 0:
            return
        try:
            loop = asyncio.get_running_loop()
            self._janitor_task = loop.create_task(self._janitor_loop())
        except RuntimeError:
            # No running event loop (test context or early import). The janitor
            # will not start — this is fine, retention enforcement only matters
            # at steady state, not in unit tests.
            pass

    def stop(self):
        self._event_bus.unsubscribe("request.captured", self._on_request)
        self._event_bus.unsubscribe("response.received", self._on_response)
        if self._janitor_task:
            self._janitor_task.cancel()
            self._janitor_task = None

    async def _janitor_loop(self):
        """Periodically purge old requests to keep the DB from growing unbounded."""
        max_req = settings.MAX_STORED_REQUESTS
        max_hours = settings.REQUEST_RETENTION_HOURS
        while True:
            try:
                await asyncio.sleep(600)  # every 10 minutes
                await self._purge_old_requests(max_req, max_hours)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Traffic janitor error: %s", exc)

    @staticmethod
    async def _purge_old_requests(max_req: int, max_hours: int):
        async with AsyncSessionLocal() as db:
            deleted = 0
            if max_req > 0:
                # Delete oldest requests beyond the cap
                count_result = await db.execute(select(func.count(Request.id)))
                count = count_result.scalar() or 0
                excess = count - max_req
                if excess > 0:
                    # Find the timestamp of the Nth-oldest request and delete
                    # everything older than that, plus a small margin
                    cutoff_result = await db.execute(
                        select(Request.id).order_by(Request.id.asc())
                        .offset(excess).limit(1)
                    )
                    cutoff_id = cutoff_result.scalar()
                    if cutoff_id:
                        result = await db.execute(
                            delete(Request).where(Request.id < cutoff_id)
                        )
                        deleted += result.rowcount
            if max_hours > 0:
                cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_hours)
                result = await db.execute(
                    delete(Request).where(Request.timestamp < cutoff_time)
                )
                deleted += result.rowcount
            if deleted > 0:
                await db.commit()
                logger.info("Traffic janitor: purged %d old requests", deleted)
            else:
                await db.rollback()

    def _body(self, value):
        if value is None:
            return None, False
        return value[:self.max_body_size], len(value) > self.max_body_size

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
            existing = await db.get(Request, request_id)
            if existing:
                return
            try:
                db.add(Request(id=request_id, session_id=self._uuid(event.get("session_id"), DEFAULT_SESSION_ID), method=event.get("method", "GET")[:16], url=event.get("url", ""), host=event.get("host", "")[:512], path=event.get("path", ""), request_headers=event.get("request_headers") or {}, request_body=body, is_body_truncated=truncated))
                await db.commit()
            except IntegrityError:
                await db.rollback()

    async def _on_response(self, event: dict):
        request_id = self._uuid(event.get("request_id"), None)
        if not request_id:
            return
        body, truncated = self._body(event.get("body"))
        async with AsyncSessionLocal() as db:
            request = await db.get(Request, request_id)
            if not request:
                try:
                    request = Request(id=request_id, session_id=self._uuid(event.get("session_id"), DEFAULT_SESSION_ID), method=event.get("method", "GET")[:16], url=event.get("url", ""), host=event.get("host", "")[:512], path=event.get("path", ""), request_headers=event.get("request_headers") or {}, request_body=event.get("request_body"))
                    db.add(request)
                    await db.commit()
                    await db.refresh(request)
                except IntegrityError:
                    await db.rollback()
                    request = await db.get(Request, request_id)
                    if not request:
                        return
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
        if not await db.get(Session, MITM_SESSION_ID):
            db.add(Session(id=MITM_SESSION_ID, name="MITM Session"))
        await db.commit()
