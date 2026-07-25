import re
from modules.scanner.base_check import BaseCheck, CheckResult


class WsOriginValidationCheck(BaseCheck):
    name = "ws_origin_validation"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        upgrade = headers_lower.get("upgrade", "")
        if "websocket" not in upgrade.lower():
            return results
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao == "*" or not acao:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="WebSocket origin validation missing",
                description=f"WebSocket upgrade response has Access-Control-Allow-Origin: '{acao or 'not set'}'. WebSocket connections should validate the Origin header.",
                evidence=f"Upgrade: {upgrade}\nACAO: {acao}",
                remediation="Validate the Origin header on the server-side during WebSocket handshake against a whitelist of allowed origins.",
                cwe="CWE-346",
            ))
        return results
