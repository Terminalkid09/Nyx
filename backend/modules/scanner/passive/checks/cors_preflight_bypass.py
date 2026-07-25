import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsPreflightBypassCheck(BaseCheck):
    name = "cors_preflight_bypass"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        acam = headers_lower.get("access-control-allow-methods", "")
        acah = headers_lower.get("access-control-allow-headers", "")
        if "*" in acam or "*" in acah:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CORS preflight bypass via wildcard",
                description=f"Access-Control-Allow-Methods or Access-Control-Allow-Headers contains wildcard '*', allowing any method/header in preflight.",
                evidence=f"ACA-Methods: {acam}\nACA-Headers: {acah}",
                remediation="Restrict Access-Control-Allow-Methods and Access-Control-Allow-Headers to specific values needed by the application.",
                cwe="CWE-942",
            ))
        return results
