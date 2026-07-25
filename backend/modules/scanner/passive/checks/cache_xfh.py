import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheXfhCheck(BaseCheck):
    name = "cache_xfh"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        x_cache = headers_lower.get("x-cache", "")
        age = headers_lower.get("age", "")
        is_cached = ("hit" in x_cache.lower() or (age.isdigit() and int(age) > 0))
        if not is_cached:
            return results
        req_headers = request_data.get("headers", {}) or {}
        req_lower = {k.lower(): str(v) for k, v in req_headers.items()}
        xfh = req_lower.get("x-forwarded-host", "")
        if xfh:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Cache poisoning via X-Forwarded-Host",
                description="X-Forwarded-Host header present in cached request. If the cache does not key on this header, attackers can poison cached redirects or resources.",
                evidence=f"X-Forwarded-Host: {xfh}\nX-Cache: {x_cache}",
                remediation="Include X-Forwarded-Host in the cache key or disable caching for responses that depend on this header.",
                cwe="CWE-444",
            ))
        return results
