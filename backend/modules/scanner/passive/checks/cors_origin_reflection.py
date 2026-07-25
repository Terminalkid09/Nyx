import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsOriginReflectionCheck(BaseCheck):
    name = "cors_origin_reflection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        req_headers = request_data.get("headers", {}) or {}
        req_origin = req_headers.get("origin", req_headers.get("Origin", ""))
        acao = headers_lower.get("access-control-allow-origin", "")
        if req_origin and acao == req_origin:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="CORS origin reflection",
                description=f"The Origin header '{req_origin}' is reflected verbatim in Access-Control-Allow-Origin. This allows any site to make CORS requests.",
                evidence=f"Request-Origin: {req_origin}\nACAO: {acao}",
                remediation="Whitelist specific origins instead of reflecting the Origin header back. Use a server-side allowlist.",
                cwe="CWE-942",
            ))
        return results
