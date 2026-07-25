import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheUnkeyedQueryCheck(BaseCheck):
    name = "cache_unkeyed_query"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        x_cache = headers_lower.get("x-cache", "")
        cf_cache = headers_lower.get("cf-cache-status", "")
        age = headers_lower.get("age", "")
        is_cached = ("hit" in x_cache.lower() or "hit" in cf_cache.lower() or (age.isdigit() and int(age) > 0))
        if is_cached:
            url = request_data.get("url", "") or event.get("url", "")
            if "?" in url:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Cache poisoning via unkeyed query parameter",
                    description=f"Cached response served for URL with query string. If query parameters are not part of the cache key, cache poisoning is possible.",
                    evidence=f"URL: {url}\nX-Cache: {x_cache}\nCF-Cache: {cf_cache}\nAge: {age}",
                    remediation="Ensure all relevant query parameters are included in the cache key. Use Vary header appropriately.",
                    cwe="CWE-444",
                ))
        return results
