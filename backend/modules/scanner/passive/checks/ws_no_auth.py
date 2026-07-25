import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsNoAuthCheck(BaseCheck):
    name = "ws_no_auth"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        upgrade = headers_lower.get("upgrade", "")
        if "websocket" not in upgrade.lower():
            return results
        auth_headers = ["authorization", "sec-websocket-protocol", "x-api-key", "api-key"]
        has_auth = any(h in headers_lower for h in auth_headers)
        if not has_auth:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="WebSocket authentication missing",
                description="WebSocket upgrade request/response does not include authentication headers or protocols.",
                evidence=f"Upgrade: {upgrade}\nHeaders: {dict(headers_lower)[:200]}",
                remediation="Implement authentication for WebSocket connections. Use tokens in the initial handshake or Sec-WebSocket-Protocol.",
                cwe="CWE-287",
            ))
        return results
