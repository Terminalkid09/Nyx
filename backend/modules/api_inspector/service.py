import json
import logging
from core.events.bus import EventBus

logger = logging.getLogger(__name__)


class ApiInspector:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus

    def register(self):
        self.event_bus.subscribe("response.received", self._classify)

    def unregister(self):
        self.event_bus.unsubscribe("response.received", self._classify)

    async def _classify(self, event):
        headers = event.get("headers", {}) or {}
        content_type = headers.get("content-type", "") or headers.get("Content-Type", "") or ""
        body = event.get("body", "") or ""
        url = event.get("url", "") or ""

        api_type = None
        if "application/grpc" in content_type:
            api_type = "grpc"
        elif self._is_graphql(body, url):
            api_type = "graphql"
        elif "application/json" in content_type:
            api_type = "rest"

        if api_type:
            await self._update_api_type(event.get("request_id"), api_type)

    async def _update_api_type(self, request_id, api_type):
        if not request_id:
            return
        try:
            from core.storage.database import AsyncSessionLocal
            from core.storage.models import Request
            from sqlalchemy import update
            import uuid
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(Request)
                    .where(Request.id == uuid.UUID(str(request_id)))
                    .values(api_type=api_type)
                )
                await db.commit()
        except Exception as e:
            logger.error("Failed to update api_type: %s", e)

    def _is_graphql(self, body: str, url: str) -> bool:
        if "graphql" in url.lower():
            return True
        try:
            parsed = json.loads(body)
            return isinstance(parsed, dict) and (
                "data" in parsed or "errors" in parsed or "query" in parsed
            )
        except Exception:
            return False
