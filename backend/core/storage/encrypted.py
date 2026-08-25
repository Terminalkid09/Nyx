"""Optional SQLCipher encrypted database support.

When NYX_SQLCIPHER_KEY is set (via env var or .env), the database is encrypted
at rest using SQLCipher (AES-256-CBC). If the key is not set or sqlcipher3 is
not installed, falls back to plain SQLite — no change in behavior.

This provides protection against casual file-system access (e.g., an attacker
who steals a copy of nyx.db from the user's AppData directory). Full disk
encryption (BitLocker/FileVault) is still recommended for defense in depth.

Usage:
    set NYX_SQLCIPHER_KEY=your-strong-password-here

Dependencies:
    pip install pysqlcipher3   (optional; silently degrades to plain SQLite)
"""
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_SQLCIPHER_KEY = os.environ.get("NYX_SQLCIPHER_KEY", "")


def is_sqlcipher_available() -> bool:
    """Check if pysqlcipher3 is installed and functional."""
    if not _SQLCIPHER_KEY:
        return False
    try:
        import sqlcipher3  # noqa: F401
        return True
    except ImportError:
        return False


def configure_sqlcipher_engine(engine) -> None:
    """Configure a SQLAlchemy engine for SQLCipher encryption.

    Must be called BEFORE the engine is used for the first time (i.e., before
    ``init_db()``). If sqlcipher3 is not available, this is a no-op and
    the default plain SQLite driver is used.

    The key is injected via SQLAlchemy's ``connect_args`` event handler,
    which is the standard way to pass PRAGMA statements on connection.
    """
    if not _SQLCIPHER_KEY:
        return

    if not is_sqlcipher_available():
        logger.warning(
            "NYX_SQLCIPHER_KEY is set but pysqlcipher3 is not installed. "
            "Database will NOT be encrypted. Install with: pip install pysqlcipher3"
        )
        return

    from sqlalchemy import event

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlcipher_key(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute(f"PRAGMA key = '{_SQLCIPHER_KEY}'")
        cursor.execute("PRAGMA cipher_compatibility = 3")
        cursor.execute("PRAGMA kdf_iter = 256000")
        cursor.close()

    logger.info(
        "SQLCipher encryption enabled (AES-256-CBC, kdf_iter=256000). "
        "Database will be encrypted at rest."
    )


def get_database_url_for_sqlcipher(url: str) -> str:
    """Replace the sqlite+aiosqlite:// driver with sqlcipher+aiosqlite://.

    If sqlcipher3 is not installed, returns the original URL unchanged.
    """
    if not _SQLCIPHER_KEY:
        return url
    if not is_sqlcipher_available():
        return url
    return url.replace("sqlite+aiosqlite://", "sqlite+pysqlcipher://")