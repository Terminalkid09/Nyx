"""Single owner of the ``nyx.secret`` file.

Both the settings module (SECRET_KEY) and the API-auth module (API key) need
persisted secrets. This store is the ONLY code that reads/writes the file, so
concurrent first-boot writes can never clobber each other's key.

In packaged builds ``NYX_HOME`` is set by the Electron shell to
``%APPDATA%/nyx-desktop/data/``. In dev mode it falls back to the project's
``backend/data/`` directory (never the project root, which would risk
accidental commits).
"""
import json
import logging
import os
import secrets
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_SECRET_DIR = Path(
    os.environ.get("NYX_HOME")
    or Path(__file__).resolve().parent.parent / "data"
)
_SECRET_DIR.mkdir(parents=True, exist_ok=True)
SECRET_FILE = _SECRET_DIR / "nyx.secret"

_lock = threading.Lock()


def _read_all() -> dict:
    if SECRET_FILE.exists():
        try:
            data = json.loads(SECRET_FILE.read_text())
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _write_all(data: dict) -> None:
    try:
        SECRET_FILE.write_text(json.dumps(data, indent=2))
        os.chmod(str(SECRET_FILE), 0o600)
    except Exception as e:
        logger.warning("Could not persist secrets to %s: %s", SECRET_FILE, e)


def get_or_create(name: str, generator) -> str:
    """Return the stored secret ``name``, creating and persisting it if absent."""
    with _lock:
        data = _read_all()
        value = data.get(name, "")
        if isinstance(value, str) and len(value) >= 16:
            return value
        value = generator()
        data[name] = value
        _write_all(data)
        return value


def api_key() -> str:
    return get_or_create("api_key", lambda: secrets.token_urlsafe(32))


def secret_key() -> str:
    return get_or_create("secret_key", lambda: secrets.token_hex(32))
