import logging
from pathlib import Path

from pydantic_settings import BaseSettings

from core.secrets_store import secret_key as _stored_secret_key

logger = logging.getLogger(__name__)


def _load_secret_key() -> str:
    return _stored_secret_key()


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

    # When False (or when the Nyx CA is NOT installed in the local OS trust
    # store), the proxy stops forcing TLS MITM: HTTPS flows are tunnelled
    # untouched (CONNECT passthrough) and only plain-HTTP traffic is
    # intercepted. This prevents the certificate-alert loop seen on target
    # devices when the CA cannot be trusted yet.
    TLS_MITM: bool = True

    # Hosts that are never MITM'd — traffic to them is tunneled untouched.
    # These are OS vendor connectivity/telemetry endpoints that, when
    # intercepted, trigger "captive portal" / "untrusted network" alerts on
    # the target device (Samsung/Google/iOS captive detection, Play Protect).
    PROXY_IGNORE_HOSTS: list[str] | None = None

    # Traffic retention: how many intercepted requests to keep in the local DB
    # before the janitor starts deleting the oldest ones. 0 = unlimited
    # (dangerous: the DB can grow to hundreds of MB).
    MAX_STORED_REQUESTS: int = 100_000
    # How many hours to keep intercepted requests (0 = unlimited).
    REQUEST_RETENTION_HOURS: int = 168  # 7 days

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
