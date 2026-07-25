import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsNoRateLimitCheck(BaseCheck):
    name = "ws_no_rate_limit"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        upgrade = headers_lower.get("upgrade", "")
        if "websocket" in upgrade.lower() and not body:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="WebSocket rate limiting missing",
                description="WebSocket connection established. WebSocket endpoints often lack rate limiting, enabling abuse or DoS attacks.",
                evidence=f"Upgrade: {upgrade}\nNo rate limit headers detected",
                remediation="Implement rate limiting on WebSocket connections. Limit messages per second per connection and total concurrent connections.",
                cwe="CWE-770",
            ))
        return results
