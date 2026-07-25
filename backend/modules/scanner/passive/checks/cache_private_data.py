import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CachePrivateDataCheck(BaseCheck):
    name = "cache_private_data"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"\\b(password|secret|token|ssn|credit.card)\\b.*200.*OK", "Sensitive data in cacheable response"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Private Data in Public Cache",
                    description="Response contains private/sensitive data but is marked as publicly cacheable or is missing cache-control: private.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Add Cache-Control: private header for responses containing sensitive data. Use no-cache/no-store for highly sensitive information.",
                    cwe="CWE-525",
                ))
                break

        return results
