import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsNoWssCheck(BaseCheck):
    name = "ws_no_wss"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        ws_patterns = [
            (r"ws://[^\s\"'<>]+", "WebSocket connection via ws:// protocol"),
            (r"new\s+WebSocket\s*\(\s*['\"]ws://", "new WebSocket() with ws:// scheme"),
            (r"WebSocket\s*\(\s*['\"]ws://", "WebSocket constructor with ws://"),
        ]
        for pattern, desc in ws_patterns:
            if re.search(pattern, body, re.IGNORECASE) or re.search(pattern, url):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="WebSocket without WSS (ws:// vs wss://)",
                    description=f"{desc}. WebSocket connections over unencrypted ws:// can be intercepted and modified by attackers.",
                    evidence=f"Pattern: {pattern}\nBody/URL: {body[:300] if body else url}",
                    remediation="Always use wss:// (WebSocket Secure) instead of ws:// for WebSocket connections to ensure encryption.",
                    cwe="CWE-319",
                ))
                break
        return results
