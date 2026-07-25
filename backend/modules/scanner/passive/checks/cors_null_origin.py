import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsNullOriginCheck(BaseCheck):
    name = "cors_null_origin"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao.lower() == "null":
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="CORS null origin allowed",
                description="Access-Control-Allow-Origin: null allows sandboxed iframes and data: URIs to make CORS requests.",
                evidence=f"ACAO: {acao}",
                remediation='Do not set Access-Control-Allow-Origin to "null". Use specific trusted origins instead.',
                cwe="CWE-942",
            ))
        return results
