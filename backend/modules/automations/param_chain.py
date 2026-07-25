import asyncio
import logging
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.events.bus import EventBus
import httpx

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
        "query", "q", "s", "filter", "order", "sort", "limit", "offset", "page",
        "callback", "jsonp", "format", "output", "response", "data", "name",
        "email", "user", "username", "pass", "password", "admin", "role",
        "method", "function", "_method", "do", "route", "controller",
    ]

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus

    async def discover(self, target_url: str, concurrency: int = 5) -> dict:
        """Try common param names on the target URL, return those that affect the response."""
        parsed = urlparse(target_url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        
        async def check_param(param: str) -> dict | None:
            params = {param: "1"}
            test_url = f"{base_url}?{urlencode(params)}"
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    # Get baseline
                    base_resp = await client.get(base_url, follow_redirects=True)
                    # Get with param
                    test_resp = await client.get(test_url, follow_redirects=True)
                    
                    if test_resp.status_code != base_resp.status_code:
                        return {"param": param, "reason": "status", "status": test_resp.status_code}
                    if len(test_resp.content) != len(base_resp.content) and abs(len(test_resp.content) - len(base_resp.content)) > 50:
                        return {"param": param, "reason": "size_diff", "size_diff": len(test_resp.content) - len(base_resp.content)}
                    # Check content difference
                    if test_resp.text != base_resp.text:
                        # Find what changed
                        return {"param": param, "reason": "content_diff"}
            except Exception:
                pass
            return None
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def limited_check(param: str) -> dict | None:
            async with semaphore:
                return await check_param(param)
        
        tasks = [limited_check(p) for p in self.COMMON_PARAMS]
        results = await asyncio.gather(*tasks)
        
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
