import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsNoInputSanitizationCheck(BaseCheck):
    name = "ws_no_input_sanitization"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\.onmessage\s*=\s*function\s*\([^)]*\)\s*\{[^}]*eval\(", "onmessage handler with eval()"),
            (r"\.onmessage\s*=\s*function\s*\([^)]*\)\s*\{[^}]*\.innerHTML\s*=", "onmessage handler with innerHTML"),
            (r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*function\s*\([^)]*\)\s*\{[^}]*\.innerHTML\s*=", "message listener with innerHTML"),
            (r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*function\s*\([^)]*\)\s*\{[^}]*document\.write\(", "message listener with document.write"),
            (r"\.onmessage\s*=\s*\(?[^)]*\)?\s*=>\s*\{[^}]*\.innerHTML\s*=", "onmessage arrow function with innerHTML"),
            (r"\.onmessage\s*=\s*\(?[^)]*\)?\s*=>\s*\{[^}]*eval\(", "onmessage arrow function with eval()"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="critical",
                    title="WebSocket input sanitization missing",
                    description=f"{desc}. WebSocket message data is used in dangerous functions without sanitization, enabling stored XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Never use WebSocket message data in eval(), innerHTML, or document.write(). Always sanitize and encode WebSocket data before DOM insertion.",
                    cwe="CWE-79",
                ))
                break
        return results
