import os
import sys
import pytest
import uuid
import base64
import json
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def event_bus():
    from core.events.bus import EventBus
    return EventBus()


@pytest.fixture
def mock_request_data():
    return {
        "method": "GET",
        "url": "https://example.com/test",
        "host": "example.com",
        "path": "/test",
        "headers": {"Host": "example.com", "User-Agent": "test"},
        "body": None,
    }


@pytest.fixture
def mock_response_data():
    return {
        "status": 200,
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx",
        },
        "body": "<html>ok</html>",
        "content_type": "text/html",
        "size_bytes": 100,
        "response_time_ms": 50,
    }


@pytest.fixture
def sample_jwt():
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "123", "name": "test", "iat": 1516239022}).encode()
    ).rstrip(b"=").decode()
    sig = "signature"
    return f"{header}.{payload}.{sig}"


@pytest.fixture
def sample_jwt_none():
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": "123", "name": "test"}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.x"
