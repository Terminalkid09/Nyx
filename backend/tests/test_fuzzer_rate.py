"""A zero rate limit means unlimited, not a crashed worker."""
import asyncio
import time

import pytest

from modules.fuzzer.service import TokenBucket


@pytest.mark.asyncio
async def test_zero_rate_is_unlimited():
    bucket = TokenBucket(0)
    started = time.monotonic()
    for _ in range(50):
        await bucket.acquire()
    assert time.monotonic() - started < 0.2


@pytest.mark.asyncio
async def test_positive_rate_still_limits():
    bucket = TokenBucket(20, burst=1)
    await bucket.acquire()
    started = time.monotonic()
    await bucket.acquire()
    assert time.monotonic() - started >= 0.02


def test_raw_http_scheme_is_inferred_from_port():
    from modules.fuzzer.service import parse_raw_scheme

    assert parse_raw_scheme("127.0.0.1:8099", "/?q=1") == "http://127.0.0.1:8099/?q=1"
    assert parse_raw_scheme("example.com", "/") == "https://example.com/"
    assert parse_raw_scheme("example.com:443", "/") == "https://example.com:443/"
    assert parse_raw_scheme("example.com:8443", "/") == "https://example.com:8443/"
    assert parse_raw_scheme("example.com:8080", "/") == "http://example.com:8080/"
    assert parse_raw_scheme("x", "http://y/z") == "http://y/z"
