import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from modules.http_client import ResponseCache, AdaptiveConcurrency, OptimizedClient, create_pooled_client


class TestResponseCache:
    def test_cache_miss(self):
        cache = ResponseCache(max_size=10, ttl_seconds=60)
        assert cache.get("GET:http://test.com") is None

    def test_cache_hit(self):
        cache = ResponseCache(max_size=10, ttl_seconds=60)
        resp = MagicMock()
        resp.status_code = 200
        cache.set("GET:http://test.com", resp)
        assert cache.get("GET:http://test.com") is resp

    def test_cache_eviction(self):
        cache = ResponseCache(max_size=2, ttl_seconds=60)
        for i in range(3):
            resp = MagicMock()
            resp.status_code = 200
            cache.set(f"key{i}", resp)
        assert cache.get("key0") is None
        assert cache.get("key2") is not None

    def test_cache_ttl(self):
        cache = ResponseCache(max_size=10, ttl_seconds=0)
        resp = MagicMock()
        cache.set("key", resp)
        time.sleep(0.01)
        assert cache.get("key") is None

    def test_cache_clear(self):
        cache = ResponseCache(max_size=10, ttl_seconds=60)
        cache.set("key", MagicMock())
        cache.clear()
        assert cache.size() == 0

    def test_cache_max_size(self):
        cache = ResponseCache(max_size=3, ttl_seconds=60)
        for i in range(5):
            cache.set(f"k{i}", MagicMock())
        assert cache.size() <= 3


class TestAdaptiveConcurrency:
    def test_initial_concurrency(self):
        ac = AdaptiveConcurrency(initial=5)
        assert ac.concurrency == 5

    def test_concurrency_bounds(self):
        ac = AdaptiveConcurrency(initial=5, min_workers=1, max_workers=10)
        ac._latencies = [0.01] * 20
        ac._adjust()
        assert ac.concurrency <= 10
        assert ac.concurrency >= 1

    def test_concurrency_increases_with_fast_latency(self):
        ac = AdaptiveConcurrency(initial=5, min_workers=1, max_workers=50)
        for _ in range(20):
            ac.record_latency(0.01)
        assert ac.concurrency > 5

    def test_concurrency_decreases_with_slow_latency(self):
        ac = AdaptiveConcurrency(initial=10, min_workers=1, max_workers=50)
        for _ in range(20):
            ac.record_latency(2.0)
        assert ac.concurrency < 10

    def test_concurrency_not_adjusted_with_few_samples(self):
        ac = AdaptiveConcurrency(initial=5)
        ac.record_latency(0.01)
        assert ac.concurrency == 5

    def test_reset(self):
        ac = AdaptiveConcurrency(initial=5)
        for _ in range(20):
            ac.record_latency(0.01)
        assert ac.concurrency != 5
        ac.reset()
        assert ac.concurrency == 5
        assert len(ac._latencies) == 0


class TestOptimizedClient:
    @pytest.mark.asyncio
    async def test_request_cached(self):
        client = OptimizedClient(http2=True, timeout=10)
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "text/css"}
        with patch("httpx.AsyncClient") as mock_http:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=resp)
            mock_http.return_value.__aenter__.return_value = mock_instance
            r1 = await client.request("GET", "http://test.com/style.css")
            assert r1 is resp
            r2 = await client.request("GET", "http://test.com/style.css")
            assert r2 is resp
            assert mock_instance.request.call_count == 1

    @pytest.mark.asyncio
    async def test_request_not_cached_for_post(self):
        client = OptimizedClient(http2=True, timeout=10)
        resp = MagicMock()
        with patch("httpx.AsyncClient") as mock_http:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=resp)
            mock_http.return_value.__aenter__.return_value = mock_instance
            await client.request("POST", "http://test.com/api")
            assert mock_instance.request.call_count == 1
            await client.request("POST", "http://test.com/api")
            assert mock_instance.request.call_count == 2

    @pytest.mark.asyncio
    async def test_cache_stats(self):
        client = OptimizedClient(http2=True, timeout=10)
        stats = client.get_cache_stats()
        assert "cache_size" in stats
        assert "concurrency" in stats
        assert "avg_latency_ms" in stats

    def test_clear_cache(self):
        client = OptimizedClient(http2=True, timeout=10)
        client._cache.set("k", MagicMock())
        assert client._cache.size() == 1
        client.clear_cache()
        assert client._cache.size() == 0

    def test_reset_concurrency(self):
        client = OptimizedClient(http2=True, timeout=10)
        for _ in range(20):
            client._adaptive.record_latency(0.01)
        old = client._adaptive.concurrency
        client.reset_concurrency()
        assert client._adaptive.concurrency != old or client._adaptive.concurrency == 5


class TestCreatePooledClient:
    def test_create_pooled_client_defaults(self):
        client = create_pooled_client()
        assert client is not None
        assert client.timeout is not None

    def test_create_pooled_client_http2(self):
        client = create_pooled_client(http2=True)
        assert client is not None

    def test_global_client(self):
        from modules.http_client import get_client
        c1 = get_client()
        c2 = get_client()
        assert c1 is c2
