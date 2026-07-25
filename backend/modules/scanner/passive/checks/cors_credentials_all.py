import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsCredentialsAllCheck(BaseCheck):
    name = "cors_credentials_all"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"Access-Control-Allow-Origin:\s*\*\s*\\n.*Access-Control-Allow-Credentials:\s*true", "Wildcard origin with credentials"),
            (r"Access-Control-Allow-Credentials:\s*true", "Credentials allowed - check origin policy"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="CORS with Access-Control-Allow-Credentials on All Origins",
                    description="Access-Control-Allow-Credentials: true combined with permissive CORS allows cross-origin requests with credentials from any domain.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Only set Access-Control-Allow-Credentials: true for specific trusted origins. Never combine with wildcard or reflected origins.",
                    cwe="CWE-942",
                ))
                break

        return results
