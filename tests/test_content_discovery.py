"""
Unit tests for Content Discovery enhancements:
- Wildcard / catch-all detection (baseline fingerprinting)
- Auto-promotion of sensitive files to findings
"""

import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from core.events.bus import EventBus
from modules.content_discovery.service import ContentDiscoveryService


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_response(status: int, content: bytes = b"OK") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = content
    return resp


# ── Wildcard Detection ────────────────────────────────────────────────────────

class TestWildcardDetection:
    """
    A server that responds 200 OK to a random UUID path is a catch-all.
    Any subsequent result with the same (status, size) signature must be discarded.
    """

    @pytest.mark.asyncio
    @patch("modules.content_discovery.service.httpx.AsyncClient")
    async def test_wildcard_server_produces_zero_results(self, mock_client_cls, tmp_path):
        """
        A catch-all server returns 200 + same body for every path.
        After wildcard detection the service must discard all those hits.
        """
        event_bus = EventBus()

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\nlogin\nbackup\n")

        wildcard_body = b"<html>Home</html>"
        wildcard_resp = _mock_response(200, wildcard_body)

        # All requests return the same wildcard response
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=wildcard_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        svc = ContentDiscoveryService(event_bus, wordlists_dir=tmp_path)
        result = await svc.discover(
            target_url="http://example.com",
            wordlist_path=str(wordlist),
        )

        assert result["discovered"] == [], \
            "Catch-all server should produce zero discovered paths"

    @pytest.mark.asyncio
    @patch("modules.content_discovery.service.httpx.AsyncClient")
    async def test_non_wildcard_server_keeps_real_results(self, mock_client_cls, tmp_path):
        """
        Wildcard probe returns 404, so none is added to wildcard_signatures.
        Any non-404 result on a real path should be kept.
        """
        event_bus = EventBus()

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("api\n")

        wildcard_resp = _mock_response(404, b"Not Found")
        real_resp = _mock_response(200, b"API endpoint found")

        call_count = {"n": 0}

        async def smart_response(*args, **kwargs):
            call_count["n"] += 1
            # First call is the wildcard probe (random UUID path)
            if call_count["n"] == 1:
                return wildcard_resp
            return real_resp

        mock_client = AsyncMock()
        mock_client.request = smart_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        svc = ContentDiscoveryService(event_bus, wordlists_dir=tmp_path)
        result = await svc.discover(
            target_url="http://example.com",
            wordlist_path=str(wordlist),
        )

        assert len(result["discovered"]) == 1
        assert result["discovered"][0]["path"] == "api"


# ── Sensitive File Auto-Promotion ─────────────────────────────────────────────

class TestSensitiveFilePromotion:

    @pytest.mark.asyncio
    @patch("modules.content_discovery.service.httpx.AsyncClient")
    async def test_env_file_emits_finding_event(self, mock_client_cls, tmp_path):
        """
        Discovering a .env file must emit a `finding.created` event with high severity.
        """
        event_bus = EventBus()
        emitted: list[dict] = []

        async def capture(event: dict):
            emitted.append(event)

        event_bus.subscribe("finding.created", capture)

        wordlist = tmp_path / "words.txt"
        wordlist.write_text(".env\n")

        wildcard_resp = _mock_response(404, b"Not Found")
        env_resp = _mock_response(200, b"DB_PASSWORD=secret\nAPP_KEY=abc123")

        call_count = {"n": 0}

        async def smart_response(*args, **kwargs):
            call_count["n"] += 1
            return wildcard_resp if call_count["n"] == 1 else env_resp

        mock_client = AsyncMock()
        mock_client.request = smart_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        svc = ContentDiscoveryService(event_bus, wordlists_dir=tmp_path)
        await svc.discover(
            target_url="http://example.com",
            wordlist_path=str(wordlist),
        )

        finding_events = [e for e in emitted if e.get("type") == "finding.created"]
        import asyncio
        await asyncio.sleep(0.05)
        finding_events = [e for e in emitted if e.get("type") == "finding.created"]
        assert len(finding_events) >= 1

        evt = finding_events[0]
        assert evt["module"] == "content_discovery"
        assert evt["severity"] == "high"
        assert evt["cwe"] == "CWE-200"
        assert ".env" in evt["title"]

    @pytest.mark.asyncio
    @patch("modules.content_discovery.service.httpx.AsyncClient")
    async def test_normal_path_does_not_emit_finding(self, mock_client_cls, tmp_path):
        """
        Discovering a normal directory (e.g. /api) must NOT emit a finding event.
        """
        event_bus = EventBus()
        emitted: list[dict] = []

        async def capture(event: dict):
            emitted.append(event)

        event_bus.subscribe("finding.created", capture)

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("api\n")

        wildcard_resp = _mock_response(404, b"Not Found")
        api_resp = _mock_response(200, b'{"version": "1.0"}')

        call_count = {"n": 0}

        async def smart_response(*args, **kwargs):
            call_count["n"] += 1
            return wildcard_resp if call_count["n"] == 1 else api_resp

        mock_client = AsyncMock()
        mock_client.request = smart_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        svc = ContentDiscoveryService(event_bus, wordlists_dir=tmp_path)
        await svc.discover(
            target_url="http://example.com",
            wordlist_path=str(wordlist),
        )

        finding_events = [e for e in emitted if e.get("type") == "finding.created"]
        assert finding_events == []

    @pytest.mark.asyncio
    @patch("modules.content_discovery.service.httpx.AsyncClient")
    async def test_backup_file_emits_finding(self, mock_client_cls, tmp_path):
        """
        .bak files are also sensitive and must trigger a finding.
        """
        event_bus = EventBus()
        emitted: list[dict] = []

        async def capture(event: dict):
            emitted.append(event)

        event_bus.subscribe("finding.created", capture)

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("config.bak\n")

        wildcard_resp = _mock_response(404, b"Not Found")
        bak_resp = _mock_response(200, b"old config content")

        call_count = {"n": 0}

        async def smart_response(*args, **kwargs):
            call_count["n"] += 1
            return wildcard_resp if call_count["n"] == 1 else bak_resp

        mock_client = AsyncMock()
        mock_client.request = smart_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        svc = ContentDiscoveryService(event_bus, wordlists_dir=tmp_path)
        await svc.discover(
            target_url="http://example.com",
            wordlist_path=str(wordlist),
        )

        import asyncio
        await asyncio.sleep(0.05)
        finding_events = [e for e in emitted if e.get("type") == "finding.created"]
        assert len(finding_events) >= 1
