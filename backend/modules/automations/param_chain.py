import asyncio
import logging
import uuid
from urllib.parse import urlparse, urlencode, urlunparse

import httpx

from core.authorization import authorize
from core.events.bus import EventBus
from core.roe import pace

logger = logging.getLogger(__name__)


class ParamDiscoveryService:
    """
    Discovers hidden parameters by fuzzing common param names,
    then automatically chains them: discovered param -> fuzz it -> scan the result.
    """

    COMMON_PARAMS = [
        "id", "page", "file", "path", "action", "cmd", "exec", "debug", "test",
        "token", "key", "secret", "api", "version", "type", "mode", "lang",
        "redirect", "url", "next", "return", "view", "template", "cat", "dir",
        "include", "require", "read", "show", "download", "upload", "search",
        "query", "q", "s", "filter", "order", "sort", "limit", "offset",
        "callback", "jsonp", "format", "output", "response", "data", "name",
        "email", "user", "username", "pass", "password", "admin", "role",
        "method", "function", "_method", "do", "route", "controller",
    ]

    # A size change smaller than this is page noise (timestamps, CSRF tokens),
    # not evidence that the parameter reached the application logic.
    MIN_SIZE_DELTA_BYTES = 200
    MIN_SIZE_DELTA_RATIO = 0.05

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus

    async def discover(
        self, target_url: str, concurrency: int = 5, session_id: str | None = None
    ) -> dict:
        """Try common param names on the target URL, return those that affect the response."""
        allowed, kind, detail = await authorize(session_id, target_url)
        if not allowed:
            await self.event_bus.publish({
                "type": "param_discovery.blocked",
                "target_url": target_url,
                "reason": kind,
                "rule": detail,
            })
            return {
                "target_url": target_url,
                "discovered_params": [],
                "total_checked": 0,
                "found": 0,
                "blocked": True,
                "error": f"Target not authorized ({kind}: {detail})",
            }

        parsed = urlparse(target_url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            await pace(base_url)
            try:
                baseline = await client.get(base_url)
            except Exception as e:
                logger.debug("Param discovery baseline failed: %s", e)
                baseline = None

            semaphore = asyncio.Semaphore(max(1, concurrency))

            async def check_param(param: str) -> dict | None:
                magic_payload = f"nyx_reflect_test_{uuid.uuid4().hex[:8]}"
                test_url = f"{base_url}?{urlencode({param: magic_payload})}"
                allowed, kind, detail = await authorize(session_id, test_url)
                if not allowed:
                    await self.event_bus.publish({
                        "type": "param_discovery.blocked",
                        "target_url": test_url,
                        "reason": kind,
                        "rule": detail,
                    })
                    return None
                try:
                    async with semaphore:
                        await pace(test_url)
                        response = await client.get(test_url)
                except Exception:
                    return None

                # 1. Reflection is the strongest signal (XSS / SSTI / injection).
                if magic_payload in (response.text or ""):
                    return {"param": param, "reason": "reflected", "payload": magic_payload}

                if baseline is None:
                    return None

                # 2. A different status code than the untouched page.
                if response.status_code != baseline.status_code:
                    return {
                        "param": param,
                        "reason": "status",
                        "status": response.status_code,
                    }

                # 3. A significant size change. Plain "text differs" was
                # useless: every response embeds a timestamp or nonce.
                delta = len(response.content) - len(baseline.content)
                if abs(delta) >= self.MIN_SIZE_DELTA_BYTES and abs(delta) >= (
                    len(baseline.content) * self.MIN_SIZE_DELTA_RATIO
                ):
                    return {"param": param, "reason": "size_diff", "size_diff": delta}
                return None

            results = await asyncio.gather(
                *(check_param(p) for p in self.COMMON_PARAMS)
            )

        discovered = [r for r in results if r is not None]

        await self.event_bus.publish({
            "type": "param_discovery.completed",
            "target_url": target_url,
            "params_discovered": len(discovered),
            "params": discovered,
        })

        return {
            "target_url": target_url,
            "discovered_params": discovered,
            "total_checked": len(self.COMMON_PARAMS),
            "found": len(discovered),
        }
