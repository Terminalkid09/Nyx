import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestRepeaterService:
    def test_create_tab(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        tab = svc.create_tab("test-tab")
        assert tab.name == "test-tab"
        assert tab.id is not None
        assert len(tab.request_history) == 0

    def test_create_tab_with_request_data(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        tab = svc.create_tab("imported", {"method": "POST", "url": "https://example.com/api"})
        assert len(tab.request_history) == 1
        assert tab.request_history[0].method == "POST"
        assert tab.request_history[0].url == "https://example.com/api"

    def test_close_tab(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        tab = svc.create_tab("test")
        assert svc.close_tab(tab.id) is True
        assert svc.close_tab(tab.id) is False

    def test_get_tabs(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        svc.create_tab("a")
        svc.create_tab("b")
        assert len(svc.get_tabs()) == 2

    def test_get_tab_not_found(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        assert svc.get_tab("nonexistent") is None

    def test_get_history_empty(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        tab = svc.create_tab("test")
        assert svc.get_history(tab.id) == []


class TestRepeaterSendRequest:
    @patch("modules.repeater.service.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_send_request_success(self, mock_client_class):
        from modules.repeater.service import RepeaterService
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.text = '{"ok":true}'
        mock_resp.elapsed.total_seconds.return_value = 0.15
        mock_client = AsyncMock()
        mock_client.request.return_value = mock_resp
        mock_client_class.return_value.__aenter__.return_value = mock_client

        svc = RepeaterService()
        tab = svc.create_tab("test")
        result = await svc.send_request(tab.id, "GET", "https://example.com", {}, None)
        assert result["status"] == 200
        assert result["body"] == '{"ok":true}'
        assert result["time_ms"] == 150

    @patch("modules.repeater.service.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_send_request_timeout(self, mock_client_class):
        from modules.repeater.service import RepeaterService
        from httpx import TimeoutException
        mock_client = AsyncMock()
        mock_client.request.side_effect = TimeoutException("timed out")
        mock_client_class.return_value.__aenter__.return_value = mock_client

        svc = RepeaterService()
        tab = svc.create_tab("test")
        result = await svc.send_request(tab.id, "GET", "https://example.com", {}, None)
        assert result["status"] == 504
        assert "timed out" in result["body"]

    @patch("modules.repeater.service.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_send_request_error(self, mock_client_class):
        from modules.repeater.service import RepeaterService
        mock_client = AsyncMock()
        mock_client.request.side_effect = Exception("connection refused")
        mock_client_class.return_value.__aenter__.return_value = mock_client

        svc = RepeaterService()
        tab = svc.create_tab("test")
        result = await svc.send_request(tab.id, "GET", "https://example.com", {}, None)
        assert result["status"] == 0
        assert "connection refused" in result["body"]

    def test_send_request_tab_not_found(self):
        from modules.repeater.service import RepeaterService
        svc = RepeaterService()
        import asyncio
        result = asyncio.run(svc.send_request("nonexistent", "GET", "https://example.com", {}, None))
        assert result is None
