import pytest
from core.events.bus import EventBus


@pytest.mark.asyncio
class TestEventBus:
    async def test_subscribe_and_publish(self, event_bus):
        received = []

        async def handler(event):
            received.append(event["data"])

        event_bus.subscribe("test.event", handler)
        await event_bus.publish({"type": "test.event", "data": "hello"})
        await _drain()
        assert received == ["hello"]

    async def test_multiple_handlers(self, event_bus):
        received = []

        async def handler1(event):
            received.append("h1")

        async def handler2(event):
            received.append("h2")

        event_bus.subscribe("test.event", handler1)
        event_bus.subscribe("test.event", handler2)
        await event_bus.publish({"type": "test.event", "data": "x"})
        await _drain()
        assert "h1" in received
        assert "h2" in received

    async def test_handler_error_does_not_crash_bus(self, event_bus):
        received = []

        async def failing_handler(event):
            raise ValueError("oops")

        async def good_handler(event):
            received.append("ok")

        event_bus.subscribe("test.event", failing_handler)
        event_bus.subscribe("test.event", good_handler)
        await event_bus.publish({"type": "test.event"})
        await _drain()
        assert received == ["ok"]

    async def test_unsubscribe_not_supported_directly(self, event_bus):
        received = []

        async def handler(event):
            received.append("called")

        event_bus.subscribe("test.event", handler)
        event_bus._subscribers["test.event"].remove(handler)
        await event_bus.publish({"type": "test.event"})
        await _drain()
        assert received == []

    async def test_no_handlers_does_not_raise(self, event_bus):
        await event_bus.publish({"type": "nonexistent"})

    async def test_publish_without_type_key(self, event_bus):
        await event_bus.publish({"data": "no type"})


async def _drain():
    import asyncio
    for _ in range(5):
        await asyncio.sleep(0.001)
