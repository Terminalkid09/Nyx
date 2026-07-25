import asyncio
from collections import defaultdict
from typing import Callable, Awaitable

Handler = Callable[[dict], Awaitable[None]]

class EventBus:
    """An async publish-subscribe event bus."""
    def __init__(self):
        """Initialise the event bus with an empty subscriber registry."""
        self._subscribers: dict[str, list[Handler]] = defaultdict(list)
        self._tasks: set[asyncio.Task] = set()

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
            task = asyncio.create_task(self._safe_call(handler, event))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _safe_call(self, handler: Handler, event: dict):
        """Call a handler and log any exception without propagating it."""
        try:
            await handler(event)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(
                "Handler error for %s: %s", event.get("type"), e
            )
