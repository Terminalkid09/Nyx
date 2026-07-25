import pytest
from unittest.mock import AsyncMock


@pytest.fixture
def engine():
    from modules.automation.engine import AutoScanEngine
    bus = AsyncMock()
    passive = AsyncMock()
    active = AsyncMock()
    return AutoScanEngine(bus, passive, active)


class TestAutoScanEngine:
    def test_initial_state(self, engine):
        assert engine._running is False
        assert engine._learning_mode is True
        assert engine.auto_active_scan is True
        assert engine.max_concurrent_active_scans == 3
        assert engine.scan_delay_ms == 500

    def test_start_stop(self, engine):
        import asyncio
        asyncio.run(engine.start())
        assert engine._running is True
        engine.stop()
        assert engine._running is False

    def test_discover_url(self, engine):
        engine._add_discovered("https://example.com/test", "request", {})
        assert "https://example.com/test" in engine.discovered_urls
        assert engine.discovered_urls["https://example.com/test"]["source"] == "request"

    def test_discover_duplicate_url(self, engine):
        engine._add_discovered("https://example.com/test", "request", {})
        engine._add_discovered("https://example.com/test", "response", {})
        assert len(engine.discovered_urls) == 1

    def test_get_discovered_urls(self, engine):
        engine._add_discovered("https://a.com", "req", {})
        engine._add_discovered("https://b.com", "res", {})
        urls = engine.get_discovered_urls()
        assert len(urls) == 2

    def test_get_pending_scans_empty(self, engine):
        assert engine.get_pending_scans() == []

    def test_extract_urls_from_body(self, engine):
        body = 'href="https://example.com/test" src="/static/js/app.js"'
        urls = engine._extract_urls_from_body(body, "text/html")
        assert "https://example.com/test" in urls
        assert "/static/js/app.js" in urls

    def test_extract_urls_from_request(self, engine):
        event = {"url": "https://example.com/page?next=https://target.com/callback"}
        urls = engine._extract_urls_from_request(event)
        assert "https://target.com/callback" in urls

    def test_get_redirect_url_found(self, engine):
        event = {"headers": {"location": "https://redirected.com"}}
        assert engine._get_redirect_url(event) == "https://redirected.com"

    def test_get_redirect_url_missing(self, engine):
        event = {"headers": {}}
        assert engine._get_redirect_url(event) is None

    def test_extract_api_endpoints(self, engine):
        body = 'href="/api/v1/users" action="/graphql"'
        endpoints = engine._extract_api_endpoints(body)
        assert "/api/v1/users" in endpoints
        assert "/graphql" in endpoints

    def test_get_config(self, engine):
        cfg = engine.get_config()
        assert cfg["auto_active_scan"] is True
        assert cfg["max_concurrent"] == 3
        assert cfg["scan_delay_ms"] == 500

    def test_update_config(self, engine):
        engine.update_config({"auto_active_scan": False, "max_concurrent": 5, "scan_delay_ms": 1000})
        assert engine.auto_active_scan is False
        assert engine.max_concurrent_active_scans == 5
        assert engine.scan_delay_ms == 1000

    def test_get_auto_scope_initial(self, engine):
        scope = engine.get_auto_scope()
        assert scope == {"include": [], "exclude": []}

    def test_enqueue_scan(self, engine):
        engine._enqueue_scan("https://example.com/api/v1/users?q=1", ["q"], {})
        assert len(engine.pending_queue) == 1
        assert engine.pending_queue[0]["priority"] == 2

    def test_enqueue_scan_lower_priority(self, engine):
        engine._enqueue_scan("https://example.com/page?q=1", ["q"], {})
        assert engine.pending_queue[0]["priority"] == 1


class TestAutoScopeLearning:
    def test_learning_adds_domain(self, engine):
        import asyncio
        asyncio.run(engine._learn_from_traffic("https://example.com/page"))
        assert "example.com" in engine._learning_domains

    def test_learning_counts_paths(self, engine):
        import asyncio
        asyncio.run(engine._learn_from_traffic("https://example.com/api"))
        assert engine._learning_paths.get("/api", 0) == 1

    def test_build_auto_scope(self, engine):
        engine._learning_domains.add("example.com")
        scope = engine._build_auto_scope()
        assert "example.com" in scope["include"]
        assert len(scope["exclude"]) > 0
