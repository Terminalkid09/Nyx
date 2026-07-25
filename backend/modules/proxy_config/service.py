from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import UpstreamProxy
from sqlalchemy import select
import logging

logger = logging.getLogger(__name__)

class ProxyConfigService:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._active_config: dict | None = None

    async def get_active(self) -> dict | None:
        """Get the currently enabled proxy config from DB and cache it."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(UpstreamProxy).where(UpstreamProxy.enabled == True).limit(1)
            )
            proxy = result.scalar_one_or_none()
            if proxy:
                self._active_config = {
                    "id": str(proxy.id),
                    "host": proxy.host,
                    "port": proxy.port,
                    "protocol": proxy.protocol,
                    "username": proxy.username,
                    "password": proxy.password,
                    "auth_enabled": proxy.auth_enabled,
                    "dns_resolution": proxy.dns_resolution,
                    "exclude_hosts": proxy.exclude_hosts,
                }
                return self._active_config
            self._active_config = None
            return None

    def get_httpx_proxy_args(self, target_host: str = "") -> dict:
        """Build httpx proxy args from active config.
        Returns dict with 'proxies' key if proxy is active,
        respecting exclude_hosts and scope_only settings.
        """
        if not self._active_config:
            return {}

        cfg = self._active_config

        # Check exclude list
        if target_host and cfg.get("exclude_hosts"):
            for excluded in cfg["exclude_hosts"]:
                if excluded in target_host:
                    return {}

        auth = ""
        if cfg.get("auth_enabled") and cfg.get("username"):
            import urllib.parse
            user = urllib.parse.quote(cfg["username"], safe="")
            pwd = urllib.parse.quote(cfg.get("password", ""), safe="")
            auth = f"{user}:{pwd}@"

        proxy_url = f"{cfg.get('protocol', 'http')}://{auth}{cfg['host']}:{cfg['port']}"

        return {"proxies": {"http://": proxy_url, "https://": proxy_url}}

    def get_playwright_proxy_args(self, target_host: str = "") -> dict | None:
        """Build Playwright proxy config from active settings."""
        if not self._active_config:
            return None

        cfg = self._active_config
        if target_host and cfg.get("exclude_hosts"):
            for excluded in cfg["exclude_hosts"]:
                if excluded in target_host:
                    return None

        server = f"{cfg.get('protocol', 'http')}://{cfg['host']}:{cfg['port']}"
        result = {"server": server}

        if cfg.get("auth_enabled") and cfg.get("username"):
            result["username"] = cfg["username"]
            result["password"] = cfg.get("password", "")

        return result

    def clear_cache(self):
        self._active_config = None
