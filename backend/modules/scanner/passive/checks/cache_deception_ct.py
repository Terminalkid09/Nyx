import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheDeceptionCtCheck(BaseCheck):
    name = "cache_deception_ct"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        ct = headers_lower.get("content-type", "")
        x_cache = headers_lower.get("x-cache", "")
        age = headers_lower.get("age", "")
        is_cached = ("hit" in x_cache.lower() or (age.isdigit() and int(age) > 0))
        is_dynamic = any(t in ct for t in ["text/html", "application/json", "application/xml"])
        is_static_ext = any(request_data.get("path", "").endswith(e) for e in [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf"])
        if is_cached and is_dynamic and is_static_ext:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Cache deception via content type confusion",
                description=f"Dynamic content ({ct}) is served with a static file extension and is cached. This enables cache deception attacks.",
                evidence=f"Path: {request_data.get('path', '')}\nContent-Type: {ct}\nX-Cache: {x_cache}",
                remediation="Configure caching rules based on content-type rather than file extension. Use X-Content-Type-Options: nosniff.",
                cwe="CWE-444",
            ))
        return results
