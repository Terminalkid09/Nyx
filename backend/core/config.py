import logging
import os
from pathlib import Path

from pydantic_settings import BaseSettings

from core.secrets_store import secret_key as _stored_secret_key

logger = logging.getLogger(__name__)


_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _default_database_url() -> str:
    """Anchor the SQLite file to a stable directory (BUG-08).

    The old default was ``sqlite+aiosqlite:///nyx.db``, resolved against the
    process CWD: starting Nyx from the repo root and from ``backend/`` produced
    two different databases with two different histories. Prefer NYX_HOME (the
    packaged app sets it), then keep using an existing file from either old
    location so no user data is orphaned, then fall back to the project root.
    """
    home = os.environ.get("NYX_HOME")
    if home:
        return f"sqlite+aiosqlite:///{(Path(home) / 'nyx.db').as_posix()}"
    for candidate in (
        Path.cwd() / "nyx.db",
        _PROJECT_ROOT / "backend" / "nyx.db",
        _PROJECT_ROOT / "nyx.db",
    ):
        if candidate.exists():
            return f"sqlite+aiosqlite:///{candidate.as_posix()}"
    return f"sqlite+aiosqlite:///{(_PROJECT_ROOT / 'nyx.db').as_posix()}"


def _load_secret_key() -> str:
    return _stored_secret_key()


class Settings(BaseSettings):
    DATABASE_URL: str = _default_database_url()
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

    # Host header values accepted by the API. The default set is the desktop
    # app's loopback addresses; "test"/"testserver" are the Starlette test
    # client defaults. Add a host here only if you deliberately front the API
    # with a reverse proxy (SEC-03: DNS rebinding sends Host: attacker.tld).
    API_ALLOWED_HOSTS: str = ""
    # Reverse proxies allowed to call the API without an X-API-Key. Used by the
    # Docker compose stack (nginx -> backend). Keep empty for a plain desktop
    # install; loopback is always trusted.
    TRUSTED_PROXY_CIDRS: str = ""
    # SEC-03b: loopback alone is not a boundary — any local process can call
    # 127.0.0.1:8000. When True, requests must also carry the X-Nyx-Token that
    # the backend generates at boot and writes to NYX_HOME/session.token; the
    # packaged desktop shell reads that file and hands it to the renderer.
    # Off by default so development and the CLI keep working unchanged.
    API_REQUIRE_SESSION_TOKEN: bool = False
    # API rate limiting (token bucket per client IP). The previous fixed
    # 100 rps / burst 50 throttled legitimate bulk sweeps of the API: the
    # full-surface sweep tripped 16 x 429 before it reached the last routes.
    # Loopback and trusted-proxy callers — the desktop UI, the CLI and the
    # endpoint sweeps — get their own, much larger budget below, while remote
    # callers keep the conservative defaults so a runaway polling loop is
    # still bounded.
    RATE_LIMIT_RPS: float = 100.0
    RATE_LIMIT_BURST: int = 50
    RATE_LIMIT_RPS_LOCAL: float = 600.0
    RATE_LIMIT_BURST_LOCAL: int = 300
    # A paused interceptor flow resumes automatically after this many seconds
    # (0 disables). Without a TTL the target's connection hangs forever if the
    # user closes the UI while an item is paused (BUG-09).
    INTERCEPTOR_PAUSE_TTL_SECONDS: int = 120
    # Hard limit for a single active check. One hung probe used to block the
    # whole sequential scan (BUG-07).
    SCAN_CHECK_TIMEOUT_SECONDS: float = 60.0
    # Refuse to probe a URL outside the session's scope rules (BUG-06).
    SCAN_ENFORCE_SCOPE: bool = True
    # Independent checks run concurrently (network-bound), bounded so a scan
    # does not flood the target. Results are still deduplicated in order.
    SCAN_MAX_CONCURRENCY: int = 4
    # Domains the proxy logger drops as noise (health checks, OCSP, ...).
    # Empty list means "use the built-in defaults".
    PROXY_NOISE_DOMAINS: str = ""

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
