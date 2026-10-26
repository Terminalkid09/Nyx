import logging
import sys
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from core.config import settings
from core.storage.models import Base

logger = logging.getLogger(__name__)

# Optional: configure SQLCipher encryption at-rest if NYX_SQLCIPHER_KEY is set.
from core.storage.encrypted import configure_sqlcipher_engine, is_sqlcipher_available

_db_url = settings.DATABASE_URL
if is_sqlcipher_available():
    # Replace the plain sqlite driver with sqlcipher-aware driver
    _db_url = _db_url.replace("sqlite+aiosqlite://", "sqlite+pysqlcipher://")
    logger.info("SQLCipher driver detected — database will be encrypted at rest")

_is_sqlite = _db_url.startswith("sqlite")
_connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_async_engine(
    _db_url,
    echo=settings.DEBUG,
    connect_args=_connect_args,
    **( {} if _is_sqlite else {"pool_size": 20, "max_overflow": 10} ),
)
# Inject PRAGMA key if SQLCipher is active
configure_sqlcipher_engine(engine)

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


async def _needs_alembic_baseline() -> bool:
    """True when the schema exists but was never tracked by alembic.

    Databases created by ``create_all`` (frozen builds, older app versions)
    hold every table but no ``alembic_version``. ``alembic upgrade head`` then
    replays the initial revision against the existing tables and dies with
    "table ... already exists", so the version is never stamped and every
    startup repeats the failure. Adopting the schema with ``alembic stamp
    head`` before the upgrade makes those databases migratable again.
    """
    from sqlalchemy import inspect

    try:
        async with engine.connect() as conn:
            tables = await conn.run_sync(lambda c: inspect(c).get_table_names())
            if not tables:
                return False
            if "alembic_version" not in tables:
                return True
            # A failed upgrade leaves an empty alembic_version behind (SQLite
            # runs DDL non-transactionally), so "table exists" is not enough:
            # no stamped revision means no migration was ever applied.
            rows = await conn.exec_driver_sql("SELECT COUNT(*) FROM alembic_version")
            return (rows.scalar() or 0) == 0
    except Exception as e:
        logger.debug("Alembic baseline detection skipped: %s", e)
        return False


async def run_alembic_migration():
    await _enable_wal()
    if _is_sqlite and not is_sqlcipher_available():
        logger.warning(
            "SQLite database is NOT encrypted at rest (%s). Intercepted bodies "
            "and cookies are stored in clear text; enable NYX_SQLCIPHER_KEY or "
            "full-disk encryption.",
            _db_url,
        )
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

    async def _alembic(*args: str):
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "alembic", *args,
            cwd=alembic_dir,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return proc.returncode, out.decode()

    try:
        if await _needs_alembic_baseline():
            logger.info("Existing schema has no alembic version — adopting it (stamp head)")
            rc, out = await _alembic("stamp", "head")
            if rc != 0:
                logger.warning("Alembic stamp exited with code %d: %s", rc, out)
        rc, out = await _alembic("upgrade", "head")
        if rc == 0:
            logger.info("Database migrations applied successfully")
        else:
            logger.warning("Alembic exited with code %d: %s", rc, out)
            raise RuntimeError(f"Alembic failed: {out}")
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
