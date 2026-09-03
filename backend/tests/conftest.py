import os
import sys
import tempfile
from pathlib import Path

import pytest
import uuid
import base64
import json
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Hermetic test database: point the app engine at an isolated temp-file DB
# *before* any test module imports core.config. Without this, API tests depend
# on whatever nyx.db happens to exist in the process cwd — a dev machine has
# one (tests silently pollute it), a fresh CI checkout does not, and every
# route touching findings/collaborator_interactions fails with
# "no such table".
_TMP_DB_DIR = tempfile.mkdtemp(prefix="nyx-test-db-")
_DB_FILE = (Path(_TMP_DB_DIR) / "nyx-test.db").as_posix()
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_DB_FILE}")


@pytest.fixture(scope="session", autouse=True)
def _init_test_database():
    """Create the app schema once for the whole test session.

    httpx's ASGITransport does not run FastAPI lifespan events, so init_db()
    never executes under TestClient-style tests: on a fresh database the
    schema would not exist at all.
    """
    import asyncio

    import core.audit  # noqa: F401 — registers AuditRecord on Base.metadata
    from core.storage.database import engine
    from core.storage.models import Base

    async def _create():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_create())
    yield


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The API middleware rate-limits every /api/ request with a process-wide
    token bucket keyed by client IP. Hundreds of API tests in one run drain it,
    and any late test then receives 429s that have nothing to do with the code
    under test (observed: test_webhook_valid_interaction failing only in the
    full suite). Refill the bucket before every test so each starts full.
    """
    from core import api_auth

    with api_auth._RATE_LIMIT_LOCK:
        api_auth._RATE_LIMIT_BUCKETS.clear()
    yield


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
