import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsWildcardCredsCheck(BaseCheck):
    name = "cors_wildcard_creds"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            results.append(CheckResult(
                triggered=True,
                severity="critical",
                title="CORS wildcard origin with credentials",
                description="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true allows any website to make authenticated requests.",
                evidence=f"ACAO: {acao}\nACAC: {acac}",
                remediation="Specify exact trusted origins instead of wildcard when using credentials. The wildcard (*) with credentials is not secure.",
                cwe="CWE-942",
            ))
        return results
