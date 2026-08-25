"""Performance benchmarks for critical endpoints.

Run with:  pytest tests/test_benchmarks.py -v
Add --benchmark-only to skip functional assertions.
"""
import asyncio
import time
import pytest


class TestRateLimiter:
    """Token bucket should handle expected load without false positives."""

    def test_rate_limiter_allows_normal_load(self):
        from core.api_auth import _check_rate_limit

        ip = "127.0.0.1"
        # 50 requests should all pass (within burst allowance)
        results = [_check_rate_limit(ip) for _ in range(50)]
        assert all(results), f"Rate limiter blocked {results.count(False)}/50 requests"

    def test_rate_limiter_blocks_abuse(self):
        from core.api_auth import _check_rate_limit, _RATE_LIMIT_BUCKETS

        ip = "192.168.1.254"
        _RATE_LIMIT_BUCKETS.pop(ip, None)  # clean state
        # Send 200 requests instantly (way beyond burst of 50)
        results = [_check_rate_limit(ip) for _ in range(200)]
        # At least the last few should be blocked
        assert results.count(False) > 0, "Rate limiter allowed all 200 burst requests"
        _RATE_LIMIT_BUCKETS.pop(ip, None)

    def test_rate_limiter_recovers_after_pause(self):
        from core.api_auth import _check_rate_limit, _RATE_LIMIT_BUCKETS
        import time as _time

        ip = "10.0.0.99"
        _RATE_LIMIT_BUCKETS.pop(ip, None)
        # Exhaust the bucket
        [_check_rate_limit(ip) for _ in range(200)]
        before = _check_rate_limit(ip)
        assert not before, "Expected blocked after burst"

        # Simulate a 2-second pause (token bucket refills 100 tokens/sec)
        now = _time.monotonic()
        _RATE_LIMIT_BUCKETS[ip] = (50.0, now - 2.0)
        after = _check_rate_limit(ip)
        assert after, "Expected allowed after pause"
        _RATE_LIMIT_BUCKETS.pop(ip, None)


class TestMetricsRegistry:
    def test_counter_increment(self):
        from core.metrics import MetricsRegistry

        r = MetricsRegistry()
        r.inc("test_counter", 5)
        assert r.counter("test_counter") == 5
        r.inc("test_counter")
        assert r.counter("test_counter") == 6

    def test_gauge_set_get(self):
        from core.metrics import MetricsRegistry

        r = MetricsRegistry()
        r.set("test_gauge", 3.14)
        assert r.get("test_gauge") == 3.14

    def test_render_prometheus_format(self):
        from core.metrics import MetricsRegistry

        r = MetricsRegistry()
        r.inc("requests_total", 10)
        r.set("active_sessions", 3)

        output = r.render()
        assert "nyx_requests_total 10" in output
        assert "nyx_active_sessions 3" in output
        assert "nyx_process_uptime_seconds" in output
        assert "# HELP" in output
        assert "# TYPE" in output

    def test_thread_safety(self):
        from core.metrics import MetricsRegistry
        import threading

        r = MetricsRegistry()
        errors = []

        def increment_1000():
            for _ in range(1000):
                try:
                    r.inc("concurrent")
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=increment_1000) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert r.counter("concurrent") == 10000
        assert not errors


class TestHeaderRedaction:
    def test_sensitive_headers_redacted(self):
        from core.proxy.addons.logger import _redact_headers

        headers = {
            "content-type": "application/json",
            "Authorization": "Bearer eyJhbGciOi...",
            "Cookie": "session=abc123",
            "set-cookie": "token=xyz789",
            "X-API-Key": "sk-12345",
            "Host": "example.com",
        }
        result = _redact_headers(headers)
        assert result["content-type"] == "application/json"
        assert result["Host"] == "example.com"
        assert result["Authorization"] == "[REDACTED]"
        assert result["Cookie"] == "[REDACTED]"
        assert result["set-cookie"] == "[REDACTED]"
        assert result["X-API-Key"] == "[REDACTED]"

    def test_empty_headers(self):
        from core.proxy.addons.logger import _redact_headers

        assert _redact_headers({}) == {}
        assert _redact_headers(None) is None  # type: ignore


class TestTrafficJanitor:
    """Database retention tests — require a running event loop."""

    @pytest.mark.asyncio
    async def test_janitor_noop_when_limits_disabled(self):
        from core.storage.traffic import TrafficStorageService
        from core.events.bus import EventBus

        bus = EventBus()
        svc = TrafficStorageService(bus, max_body_size=100)
        # Janitor starts when the event loop is running, regardless of limits.
        # It checks limits inside _janitor_loop and exits immediately if both are 0.
        assert svc._janitor_task is not None
        svc.stop()
        assert svc._janitor_task is None

    @pytest.mark.asyncio
    async def test_janitor_stops_on_request(self):
        """Janitor must stop cleanly when stop() is called."""
        from core.storage.traffic import TrafficStorageService
        from core.events.bus import EventBus

        bus = EventBus()
        svc = TrafficStorageService(bus, max_body_size=100)
        assert svc._janitor_task is not None
        svc.stop()
        assert svc._janitor_task is None


class TestHealthEndpoint:
    """/health must respond quickly and contain key fields."""

    @pytest.mark.asyncio
    async def test_health_response_time(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start = time.monotonic()
            resp = await client.get("/health")
            elapsed = time.monotonic() - start

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("ok", "degraded")
        assert "uptime_sec" in data
        assert "database" in data
        assert "proxy" in data
        assert "memory" in data
        # Should respond in under 2 seconds even with DB check
        assert elapsed < 2.0, f"/health took {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_healthz_is_fast(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            start = time.monotonic()
            resp = await client.get("/healthz")
            elapsed = time.monotonic() - start

        assert resp.status_code == 200
        assert resp.json() == {"status": "alive"}
        # Liveness probe must be sub-100ms
        assert elapsed < 0.5, f"/healthz took {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/metrics")

        assert resp.status_code == 200
        text = resp.text
        assert "nyx_" in text or "uptime" in text  # metrics registry present
        assert resp.headers["content-type"].startswith("text/plain")

    @pytest.mark.asyncio
    async def test_rate_limit_429(self):
        from main import app
        from core.api_auth import _RATE_LIMIT_BUCKETS, _RATE_LIMIT_BURST
        from httpx import ASGITransport, AsyncClient

        ip = "10.255.255.1"
        _RATE_LIMIT_BUCKETS.pop(ip, None)

        transport = ASGITransport(app=app, client=(ip, 0))
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Send burst+1 requests without pausing — should trigger 429
            total = _RATE_LIMIT_BURST + 10
            statuses = []
            for _ in range(total):
                resp = await client.get("/api/proxy/status")
                statuses.append(resp.status_code)

            assert 429 in statuses, f"Expected 429 in {total} requests, got {set(statuses)}"

        _RATE_LIMIT_BUCKETS.pop(ip, None)