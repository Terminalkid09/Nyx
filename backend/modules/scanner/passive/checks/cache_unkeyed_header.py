import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheUnkeyedHeaderCheck(BaseCheck):
    name = "cache_unkeyed_header"

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
        unkeyed_headers = ["x-forwarded-host", "x-forwarded-scheme", "x-original-url", "x-rewrite-url", "x-http-method-override", "x-http-method"]
        for hdr in unkeyed_headers:
            if hdr in req_lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title=f"Cache poisoning via unkeyed header: {hdr}",
                    description=f"The '{hdr}' header is present in the request and the response is cached. If this header is not part of the cache key, cache poisoning is possible.",
                    evidence=f"Header: {hdr}: {req_lower[hdr]}\nX-Cache: {x_cache}",
                    remediation="Ensure all potentially dangerous headers are included in the cache key or excluded from caching.",
                    cwe="CWE-444",
                ))
        return results
