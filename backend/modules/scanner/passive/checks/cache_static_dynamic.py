import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheStaticDynamicCheck(BaseCheck):
    name = "cache_static_dynamic"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"\.(js|css|png|jpg|gif|ico)\?.*\d{10,}", "Static asset with cache-busting"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Mixed Static/Dynamic Content Cached Together",
                    description="Static asset endpoints return dynamic content (different responses for same URL). This can cause cache poisoning if dynamic content is cached as static.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Separate static and dynamic content using different URL paths or subdomains. Use Cache-Control headers appropriately for each content type.",
                    cwe="CWE-525",
                ))
                break

        return results
