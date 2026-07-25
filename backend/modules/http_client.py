import httpx
import time
import logging
import asyncio
from collections import OrderedDict
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ResponseCache:
    def __init__(self, max_size: int = 500, ttl_seconds: int = 60):
        self._cache: OrderedDict[str, tuple[float, httpx.Response]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds

    def get(self, key: str) -> httpx.Response | None:
        if key not in self._cache:
            return None
        ts, resp = self._cache[key]
        if time.time() - ts > self._ttl:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return resp

    def set(self, key: str, resp: httpx.Response):
        if len(self._cache) >= self._max_size:
            self._cache.popitem(last=False)
        self._cache[key] = (time.time(), resp)

    def clear(self):
        self._cache.clear()

    def size(self) -> int:
        return len(self._cache)


class AdaptiveConcurrency:
    def __init__(self, initial: int = 5, min_workers: int = 1, max_workers: int = 50):
        self._current = initial
        self._min = min_workers
        self._max = max_workers
        self._latencies: list[float] = []
        self._window_size = 20

    def record_latency(self, seconds: float):
        self._latencies.append(seconds)
        if len(self._latencies) > self._window_size:
            self._latencies.pop(0)
        self._adjust()

    def _adjust(self):
        if len(self._latencies) < 5:
            return
        avg_latency = sum(self._latencies) / len(self._latencies)
        if avg_latency < 0.1:
            self._current = min(self._current + 2, self._max)
        elif avg_latency > 1.0:
            self._current = max(self._current - 1, self._min)
        elif avg_latency > 0.5:
            pass

    @property
    def concurrency(self) -> int:
        return self._current

    def reset(self):
        self._current = 5
        self._latencies.clear()


class OptimizedClient:
    def __init__(self, http2: bool = True, timeout: float = 30.0, cache_size: int = 500, initial_concurrency: int = 10):
        self._http2 = http2
        self._timeout = timeout
        self._cache = ResponseCache(max_size=cache_size)
        self._adaptive = AdaptiveConcurrency(initial=initial_concurrency)
        self._semaphore = asyncio.Semaphore(initial_concurrency)

    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        cache_key = f"{method}:{url}" if method == "GET" else None
        if cache_key:
            cached = self._cache.get(cache_key)
            if cached:
                logger.debug("Cache hit: %s %s", method, url)
                return cached

        async with self._semaphore:
            start = time.time()
            try:
                async with httpx.AsyncClient(
                    verify=False,
                    timeout=self._timeout,
                    http2=self._http2,
                    limits=httpx.Limits(
                        max_keepalive_connections=50,
                        max_connections=100,
                        keepalive_expiry=30.0,
                    ),
                ) as client:
                    resp = await client.request(method, url, **kwargs)
                    elapsed = time.time() - start
                    self._adaptive.record_latency(elapsed)

                    if cache_key and resp.status_code == 200:
                        content_type = resp.headers.get("content-type", "")
                        if any(ct in content_type for ct in ["text/css", "text/javascript", "application/javascript", "image/", "font/"]):
                            self._cache.set(cache_key, resp)

                    return resp
            except Exception:
                raise

    def get_cache_stats(self) -> dict:
        return {
            "cache_size": self._cache.size(),
            "concurrency": self._adaptive.concurrency,
            "avg_latency_ms": round(sum(self._adaptive._latencies) / len(self._adaptive._latencies) * 1000, 2) if self._adaptive._latencies else 0,
        }

    def clear_cache(self):
        self._cache.clear()

    def reset_concurrency(self):
        self._adaptive.reset()


_global_client: OptimizedClient | None = None


def get_client() -> OptimizedClient:
    global _global_client
    if _global_client is None:
        _global_client = OptimizedClient()
    return _global_client


def create_pooled_client(http2: bool = True, timeout: float = 30.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        http2=http2,
        limits=httpx.Limits(
            max_keepalive_connections=50,
            max_connections=100,
            keepalive_expiry=30.0,
        ),
    )
