import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsVaryHeaderCheck(BaseCheck):
    name = "cors_vary_header"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        acao = headers_lower.get("access-control-allow-origin", "")
        vary = headers_lower.get("vary", "")
        if acao and acao != "*":
            if "origin" not in vary.lower():
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="CORS Vary header missing",
                    description="Dynamic Access-Control-Allow-Origin is set but the Vary: Origin header is missing, which can cause cache poisoning.",
                    evidence=f"ACAO: {acao}\nVary: {vary}",
                    remediation="Add 'Vary: Origin' to all responses that set a dynamic Access-Control-Allow-Origin header.",
                    cwe="CWE-942",
                ))
        return results
