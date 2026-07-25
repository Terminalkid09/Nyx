import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SopBypassCheck(BaseCheck):
    name = "sop_bypass"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        body = event.get("response_body", "") or ""

        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "")

        if acao == "*" and acac.lower() == "true":
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="SOP bypass via CORS misconfiguration",
                description="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true allows any origin to read responses with credentials.",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation="Do not use wildcard origin with credentials. Specify exact trusted origins.",
                cwe="CWE-942",
            ))

        if re.search(r"document\.domain\s*=", body):
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="SOP bypass via document.domain",
                description="document.domain assignment found. This weakens the same-origin policy.",
                evidence="document.domain assignment in response body",
                remediation="Avoid using document.domain. Use postMessage and MessageChannel for cross-origin communication.",
                cwe="CWE-668",
            ))

        if re.search(r"postMessage\s*\(.*?\*", body):
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="postMessage with wildcard targetOrigin",
                description="postMessage with '*' as targetOrigin allows any window to receive messages.",
                evidence="postMessage with wildcard targetOrigin",
                remediation="Specify a specific targetOrigin instead of '*' in postMessage calls.",
                cwe="CWE-668",
            ))
        return results
