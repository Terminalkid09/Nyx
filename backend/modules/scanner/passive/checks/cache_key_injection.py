import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CacheKeyInjectionCheck(BaseCheck):
    name = "cache_key_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        if not url:
            return results
        newline_patterns = [
            (r"%0d%0a", "CRLF injection in URL (%0d%0a)"),
            (r"%0a", "LF injection in URL (%0a)"),
            (r"%0d", "CR injection in URL (%0d)"),
            (r"\r\n", "Raw CRLF in URL"),
            (r"\n", "Raw newline in URL"),
        ]
        for pattern, desc in newline_patterns:
            if re.search(pattern, url):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Cache key injection via newline",
                    description=f"{desc}. Newline characters in the URL can cause cache key injection, poisoning cached responses.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Reject requests containing newline characters in the URL. Ensure web servers and CDNs properly handle header injection attempts.",
                    cwe="CWE-444",
                ))
                break
        return results
