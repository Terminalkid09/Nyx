import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsExposedHeadersCheck(BaseCheck):
    name = "cors_exposed_headers"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"Access-Control-Expose-Headers:\s*\*", "Wildcard exposed headers"),
            (r"Access-Control-Expose-Headers:.*Set-Cookie", "Set-Cookie exposed via CORS"),
            (r"Access-Control-Expose-Headers:.*Authorization", "Authorization header exposed via CORS"),
            (r"Access-Control-Expose-Headers:.*Token", "Token header exposed via CORS"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="Overly Permissive CORS Exposed Headers",
                    description="Access-Control-Expose-Headers reveals sensitive headers to cross-origin requests. Internal headers like Set-Cookie, Authorization should not be exposed.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Only expose headers that are explicitly needed by the client application. Do not expose security-sensitive headers.",
                    cwe="CWE-942",
                ))
                break

        return results
