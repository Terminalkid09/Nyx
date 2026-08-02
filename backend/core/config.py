import json
import logging
import os
import secrets
from pathlib import Path
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

_SECRET_DIR = Path(os.environ.get("NYX_HOME") or Path(__file__).resolve().parent.parent.parent)
_SECRET_DIR.mkdir(parents=True, exist_ok=True)
_SECRET_FILE = _SECRET_DIR / "nyx.secret"


def _load_secret_key() -> str:
    data = {}
    if _SECRET_FILE.exists():
        try:
            data = json.loads(_SECRET_FILE.read_text())
            sk = data.get("secret_key", "")
            if sk and len(sk) >= 16:
                return sk
        except Exception:
            data = {}
    sk = secrets.token_hex(32)
    data["secret_key"] = sk
    try:
        _SECRET_FILE.write_text(json.dumps(data, indent=2))
        os.chmod(str(_SECRET_FILE), 0o600)
    except Exception as e:
        logger.warning("Could not persist SECRET_KEY to %s: %s", _SECRET_FILE, e)
    return sk


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///nyx.db"
    PROXY_HOST: str = "0.0.0.0"
    PROXY_PORT: int = 8080
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    COLLABORATOR_URL: str = "http://localhost:8000"
    COLLABORATOR_DOMAIN: str = "localhost"
    MAX_BODY_SIZE_BYTES: int = 10 * 1024 * 1024
    DEFAULT_SESSION_NAME: str = "Default Session"
    SECRET_KEY: str = ""
    PROXY_MODE: str = "regular"
    DEBUG: bool = False

    # Hosts that are never MITM'd — traffic to them is tunneled untouched.
    # These are OS vendor connectivity/telemetry endpoints that, when
    # intercepted, trigger "captive portal" / "untrusted network" alerts on
    # the target device (Samsung/Google/iOS captive detection, Play Protect).
    PROXY_IGNORE_HOSTS: list[str] | None = None

    model_config = {"env_file": str(Path(__file__).resolve().parent.parent.parent / ".env"), "extra": "ignore"}

    @property
    def secret_key(self) -> str:
        if not self.SECRET_KEY:
            self.SECRET_KEY = _load_secret_key()
        return self.SECRET_KEY

    @property
    def proxy_ignore_hosts(self) -> list[str]:
        """Hosts excluded from MITM (never intercepted/decrypted).

        mitmproxy treats each entry as a regex matched against the full hostname,
        so we use anchors/escaped dots to avoid accidental broad matches.
        """
        return self.PROXY_IGNORE_HOSTS or [
            r"^connectivitycheck\.(gstatic\.com|google\.com)$",
            r"^clients[0-9]*\.google\.com$",
            r"^clients[0-9]*\.android\.com$",
            r"^mr1\.gvt[0-9]*\.com$",
            r"^mtalk\.google\.com$",
            r"^gcm-http\.googleapis\.com$",
            r"^gcm-x\.googleapis\.com$",
            r"^time\.android\.com$",
            r"^www\.msftconnecttest\.com$",
            r"^connectivity-check\.centralus\.cloudapp\.azure\.com$",
            r"^captive\.apple\.com$",
            r"^gsp[0-9]*\.gs\.apple\.com$",
        ]


settings = Settings()
