import logging
import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from core.config import settings
from core.storage.models import Base

logger = logging.getLogger(__name__)

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args=_connect_args,
    **( {} if _is_sqlite else {"pool_size": 20, "max_overflow": 10} ),
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def _enable_wal():
    if not _is_sqlite:
        return
    try:
        async with engine.begin() as conn:
            await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            await conn.exec_driver_sql("PRAGMA busy_timeout=5000")
            await conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        logger.info("SQLite WAL mode enabled")
    except Exception as e:
        logger.warning("Failed to enable WAL mode: %s", e)


_ADD_COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "findings": [
        ("cvss_vector", "VARCHAR(64)"),
        ("cvss_score", "FLOAT"),
    ],
}


async def _apply_lightweight_migrations():
    """Add columns that were introduced after existing databases were created."""
    if not _is_sqlite:
        return
    try:
        async with engine.begin() as conn:
            for table, columns in _ADD_COLUMN_MIGRATIONS.items():
                existing = {
                    row[1]
                    for row in await conn.exec_driver_sql(f"PRAGMA table_info({table})")
                }
                for col_name, col_type in columns:
                    if col_name not in existing:
                        await conn.exec_driver_sql(
                            f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"
                        )
                        logger.info("Added missing column %s.%s", table, col_name)
    except Exception as e:
        logger.warning("Lightweight migration failed: %s", e)


async def run_alembic_migration():
    await _enable_wal()
    if getattr(sys, "frozen", False):
        logger.info("Frozen build detected — DATABASE_URL=%r engine=%r", settings.DATABASE_URL, type(engine).__module__)
        logger.info("Using create_all instead of alembic subprocess")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _apply_lightweight_migrations()
        logger.info("Database tables created successfully")
        return

    import asyncio.subprocess
    from pathlib import Path
    import os

    alembic_dir = str(Path(__file__).parent.parent.parent)
    env = {**os.environ, "DATABASE_URL": settings.DATABASE_URL}
    env.setdefault("PYTHONPATH", alembic_dir)
    try:
        proc = await asyncio.create_subprocess_exec(
            "alembic", "upgrade", "head",
            cwd=alembic_dir,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        if proc.returncode == 0:
            logger.info("Database migrations applied successfully")
        else:
            logger.warning("Alembic exited with code %d: %s", proc.returncode, stdout.decode())
            raise RuntimeError(f"Alembic failed: {stdout.decode()}")
    except Exception as e:
        logger.warning("Alembic migration failed (%s), falling back to create_all", e)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _apply_lightweight_migrations()
        logger.info("create_all fallback completed")


init_db = run_alembic_migration


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
