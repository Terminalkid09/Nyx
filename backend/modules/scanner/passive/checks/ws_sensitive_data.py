import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsSensitiveDataCheck(BaseCheck):
    name = "ws_sensitive_data"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        sensitive_patterns = [
            (r"\.send\s*\(\s*['\"][^'\"]*(password|token|secret|auth|credential|api.?key|jwt)[^'\"]*['\"]", "Sensitive data sent via WebSocket"),
            (r"WebSocket.*password", "WebSocket message containing 'password'"),
            (r"WebSocket.*token", "WebSocket message containing 'token'"),
            (r"WebSocket.*secret", "WebSocket message containing 'secret'"),
        ]
        for pattern, desc in sensitive_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="WebSocket sensitive data leakage",
                    description=f"{desc}. Sensitive information may be transmitted over WebSocket without encryption or proper handling.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Ensure sensitive data is never transmitted over WebSocket without encryption. Use server-side validation and proper authentication.",
                    cwe="CWE-200",
                ))
                break
        return results
