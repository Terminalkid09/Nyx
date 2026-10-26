"""Hermetic environment for the legacy root test suite.

These tests predate ``backend/tests/conftest.py`` and used to run against
whatever database happened to sit in the repository root. That made them
environment-dependent: on a fresh checkout they failed with "no such table",
and on a developer machine they read (and polluted) the real ``nyx.db`` — the
RoE gate then failed with "no such table: authorization_profiles" as soon as
a new table was added.

Point the app at a throwaway database and create the schema once per session,
before any test module imports ``core.config``.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

_TMP_DB_DIR = tempfile.mkdtemp(prefix="nyx-legacy-test-db-")
_DB_FILE = (Path(_TMP_DB_DIR) / "nyx-test.db").as_posix()
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{_DB_FILE}")
# Never let a test run clear the host's system proxy on exit.
os.environ.setdefault("NYX_SKIP_OS_CLEANUP", "1")


@pytest.fixture(scope="session", autouse=True)
def _init_test_database():
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
    """Each test starts with a full API rate-limit bucket."""
    from core import api_auth

    with api_auth._RATE_LIMIT_LOCK:
        api_auth._RATE_LIMIT_BUCKETS.clear()
    yield
