import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WebCachePoisoningCheck(BaseCheck):
    name = "web_cache_poisoning"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        body = event.get("response_body", "") or ""

        cache_poison_headers = [
            "x-forwarded-host",
            "x-original-url",
            "x-rewrite-url",
            "x-forwarded-scheme",
            "x-original-host",
            "x-http-method-override",
            "x-http-method",
            "x-method-override",
        ]
        for h in cache_poison_headers:
            if h in headers_lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Web cache poisoning header detected",
                    description=f"Request header '{h}' found. This header may be used for web cache poisoning attacks.",
                    evidence=f"Header: {h}: {headers_lower[h]}",
                    remediation="Do not use unvalidated headers in cache key computation. Use only the Host header and URL path for cache keys.",
                    cwe="CWE-444",
                ))

        reflected_headers = ["x-forwarded-host", "x-original-url", "x-rewrite-url"]
        for h in reflected_headers:
            if h in headers_lower and headers_lower[h] in body:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Cache poisoning via reflected header",
                    description=f"Header '{h}' value is reflected in the response body. This can be used for web cache poisoning.",
                    evidence=f"Header: {h}: {headers_lower[h]}\nReflected in body",
                    remediation="Do not reflect unvalidated headers in the response. Use only the Host header for cache key computation.",
                    cwe="CWE-444",
                ))
        return results
