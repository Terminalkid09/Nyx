"""Alembic must adopt a schema created by create_all instead of failing on it.

Databases created by ``create_all`` (frozen builds, older app versions) hold
every table but no stamped revision. ``alembic upgrade head`` used to replay
the initial revision, die with "table ... already exists" and leave an empty
``alembic_version`` behind, so every startup repeated the same failure.
"""
from sqlalchemy.ext.asyncio import create_async_engine

from core.storage import database


async def _with_engine(tmp_path, monkeypatch, setup=None):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'nyx.db'}")
    if setup is not None:
        async with engine.begin() as conn:
            for statement in setup:
                await conn.exec_driver_sql(statement)
    monkeypatch.setattr(database, "engine", engine)
    needs_baseline = await database._needs_alembic_baseline()
    await engine.dispose()
    return needs_baseline


async def test_empty_database_needs_no_baseline(tmp_path, monkeypatch):
    assert await _with_engine(tmp_path, monkeypatch) is False


async def test_schema_without_version_table_needs_baseline(tmp_path, monkeypatch):
    assert await _with_engine(
        tmp_path, monkeypatch, ["CREATE TABLE sessions (id VARCHAR)"]
    ) is True


async def test_empty_version_table_needs_baseline(tmp_path, monkeypatch):
    # What a failed first upgrade leaves behind on SQLite (non-transactional
    # DDL): the table exists but no revision was ever stamped.
    assert await _with_engine(
        tmp_path,
        monkeypatch,
        [
            "CREATE TABLE sessions (id VARCHAR)",
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)",
        ],
    ) is True


async def test_stamped_database_needs_no_baseline(tmp_path, monkeypatch):
    assert await _with_engine(
        tmp_path,
        monkeypatch,
        [
            "CREATE TABLE sessions (id VARCHAR)",
            "CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)",
            "INSERT INTO alembic_version VALUES ('c4f2e6989355')",
        ],
    ) is False
