import asyncio
import json
import logging
from fastapi import WebSocket
from core.events.bus import EventBus
from core.events.schemas import NyxEvent

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self, event_bus: EventBus):
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()
        self._event_bus = event_bus
        self._subscribed_events: list[str] = [
            "request.captured",
            "response.received",
            "finding.created",
            "scan.active.started",
            "scan.active.completed",
            "fuzz.progress",
            "collaborator.hit",
            "interceptor.request.paused",
            "interceptor.response.paused",
            "interceptor.item.forwarded",
            "interceptor.item.dropped",
        ]
        self._subscribe_all(event_bus)

    def _subscribe_all(self, event_bus: EventBus):
        for event_type in self._subscribed_events:
            event_bus.subscribe(event_type, self._broadcast)

    def unsubscribe_all(self):
        for event_type in self._subscribed_events:
            self._event_bus.unsubscribe(event_type, self._broadcast)

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.append(ws)

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            if ws in self._connections:
                self._connections.remove(ws)

    async def _broadcast(self, event: NyxEvent):
        data = json.dumps(
            event if isinstance(event, dict) else event.model_dump(),
            default=str,
        )
        async with self._lock:
            snapshot = list(self._connections)
        dead: list[WebSocket] = []
        for ws in snapshot:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    try:
                        self._connections.remove(ws)
                    except ValueError:
                        pass
