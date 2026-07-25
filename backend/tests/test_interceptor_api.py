import pytest
from unittest.mock import MagicMock, patch


class TestInterceptorStatusEndpoint:
    @pytest.mark.asyncio
    async def test_get_interceptor_status_enabled(self):
        from api.routes.interceptor import get_interceptor_status
        engine = MagicMock()
        engine.enabled = True
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await get_interceptor_status(request)
        assert result == {"enabled": True}

    @pytest.mark.asyncio
    async def test_get_interceptor_status_disabled(self):
        from api.routes.interceptor import get_interceptor_status
        engine = MagicMock()
        engine.enabled = False
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await get_interceptor_status(request)
        assert result == {"enabled": False}

    @pytest.mark.asyncio
    async def test_get_interceptor_status_no_engine(self):
        from api.routes.interceptor import get_interceptor_status
        from fastapi import HTTPException
        request = MagicMock()
        request.app.state.interceptor_engine = None
        with pytest.raises(HTTPException) as exc:
            await get_interceptor_status(request)
        assert exc.value.status_code == 503


class TestInterceptorToggleEndpoint:
    @pytest.mark.asyncio
    async def test_toggle_flips_enabled(self):
        from api.routes.interceptor import toggle_interceptor
        engine = MagicMock()
        engine.enabled = True
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        await toggle_interceptor(request)
        assert engine.enabled is False

    @pytest.mark.asyncio
    async def test_toggle_returns_new_state(self):
        from api.routes.interceptor import toggle_interceptor
        engine = MagicMock()
        engine.enabled = False
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await toggle_interceptor(request)
        assert result == {"enabled": True}


class TestInterceptorPausedEndpoint:
    @pytest.mark.asyncio
    async def test_get_paused_returns_items(self):
        from api.routes.interceptor import get_paused
        engine = MagicMock()
        engine.get_paused.return_value = [{"id": "1", "direction": "request"}]
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await get_paused(request)
        assert result == [{"id": "1", "direction": "request"}]

    @pytest.mark.asyncio
    async def test_get_paused_empty(self):
        from api.routes.interceptor import get_paused
        engine = MagicMock()
        engine.get_paused.return_value = []
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await get_paused(request)
        assert result == []


class TestForwardItemEndpoint:
    @pytest.mark.asyncio
    async def test_forward_item_calls_engine(self):
        from api.routes.interceptor import forward_item
        from api.routes.interceptor import ForwardModifications
        from unittest.mock import AsyncMock
        engine = MagicMock()
        engine.forward_item = AsyncMock()
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await forward_item("item-1", ForwardModifications(method="POST"), request)
        engine.forward_item.assert_awaited_once_with("item-1", {"method": "POST"})
        assert result == {"status": "forwarded"}

    @pytest.mark.asyncio
    async def test_forward_item_not_found(self):
        from api.routes.interceptor import forward_item
        from fastapi import HTTPException
        from unittest.mock import AsyncMock
        engine = MagicMock()
        engine.forward_item = AsyncMock(side_effect=ValueError("not found"))
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        with pytest.raises(HTTPException) as exc:
            await forward_item("bad-id", None, request)
        assert exc.value.status_code == 404


class TestDropItemEndpoint:
    @pytest.mark.asyncio
    async def test_drop_item_calls_engine(self):
        from api.routes.interceptor import drop_item
        from unittest.mock import AsyncMock
        engine = MagicMock()
        engine.drop_item = AsyncMock()
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        result = await drop_item("item-1", request)
        engine.drop_item.assert_awaited_once_with("item-1")
        assert result == {"status": "dropped"}

    @pytest.mark.asyncio
    async def test_drop_item_not_found(self):
        from api.routes.interceptor import drop_item
        from fastapi import HTTPException
        from unittest.mock import AsyncMock
        engine = MagicMock()
        engine.drop_item = AsyncMock(side_effect=ValueError("not found"))
        request = MagicMock()
        request.app.state.interceptor_engine = engine
        with pytest.raises(HTTPException) as exc:
            await drop_item("bad-id", request)
        assert exc.value.status_code == 404
