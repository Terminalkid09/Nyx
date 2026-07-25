import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheHostHeaderCheck(BaseCheck):
    name = "cache_host_header"

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
        req_host = req_headers.get("host", req_headers.get("Host", "")).lower()
        url = request_data.get("url", "") or event.get("url", "")
        parsed_host = ""
        if "://" in url:
            parsed_host = url.split("://")[1].split("/")[0].split(":")[0].lower()
        if req_host and parsed_host and req_host != parsed_host:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Cache poisoning via Host header",
                description=f"Request has Host header '{req_host}' which differs from the URL host '{parsed_host}'. If the cache key does not include the Host header, poisoning is possible.",
                evidence=f"Host: {req_host}\nURL host: {parsed_host}\nX-Cache: {x_cache}",
                remediation="Ensure the Host header is included in the cache key. Validate the Host header against an allowlist.",
                cwe="CWE-444",
            ))
        return results
