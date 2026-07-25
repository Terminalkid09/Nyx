import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsMessageInjectionCheck(BaseCheck):
    name = "ws_message_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\.send\s*\(\s*JSON\.stringify\s*\(\s*\{[^}]*userInput", "WebSocket.send() with user input object"),
            (r"\.send\s*\(\s*[^)]*\+\s*[^)]*\)", "WebSocket.send() with concatenated user input"),
            (r"\.send\s*\(\s*[^)]*value\)", "WebSocket.send() with .value (form input)"),
            (r"\.send\s*\(\s*[^)]*innerText\)", "WebSocket.send() with innerText"),
            (r"\.send\s*\(\s*[^)]*textContent\)", "WebSocket.send() with textContent"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="WebSocket message injection possible",
                    description=f"{desc}. User-controlled data is sent via WebSocket without sanitization, potentially enabling message injection.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Validate and sanitize all user input before sending over WebSocket. Use parameterized message formats on the server.",
                    cwe="CWE-77",
                ))
                break
        return results
