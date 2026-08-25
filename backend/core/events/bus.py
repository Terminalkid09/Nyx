import asyncio
import logging
from collections import defaultdict
from typing import Callable, Awaitable

Handler = Callable[[dict], Awaitable[None]]

# Prevent unbounded task creation when a handler is slow or blocked. Without
# this, a spike of proxy traffic could create thousands of concurrent
# ``asyncio.create_task`` calls, exhausting memory. ~50 concurrent handlers
# (DB writes, scanner checks, WebSocket broadcasts) is plenty.
_MAX_CONCURRENT_HANDLERS = 50


class EventBus:
    """An async publish-subscribe event bus."""
    def __init__(self):
        """Initialise the event bus with an empty subscriber registry."""
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._tasks: set[asyncio.Task] = set()
        self._semaphore = asyncio.Semaphore(_MAX_CONCURRENT_HANDLERS)
        self._logger = logging.getLogger(__name__)

    def subscribe(self, event_type: str, handler: Handler):
        """Register a handler for a given event type."""
        self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: Handler):
        """Remove a previously registered handler. No-op if not found."""
        handlers = self._subscribers.get(event_type)
        if handlers:
            try:
                handlers.remove(handler)
            except ValueError:
                pass

    async def publish(self, event: dict):
        """Dispatch an event to all subscribed handlers concurrently."""
        handlers = self._subscribers.get(event.get("type"), [])
        for handler in handlers:
            acquired = False
            try:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=5.0)
                acquired = True
            except asyncio.TimeoutError:
                self._logger.warning(
                    "EventBus saturated — dropping handler for event %s",
                    event.get("type"),
                )
                continue
            task = asyncio.create_task(self._safe_call(handler, event))
            self._tasks.add(task)
            task.add_done_callback(lambda t, sem=self._semaphore: sem.release())
            task.add_done_callback(self._tasks.discard)

    async def _safe_call(self, handler: Handler, event: dict):
        """Call a handler and log any exception without propagating it."""
        try:
            await handler(event)
        except Exception as exc:
            self._logger.error(
                "Handler error for %s: %s", event.get("type"), exc
            )
