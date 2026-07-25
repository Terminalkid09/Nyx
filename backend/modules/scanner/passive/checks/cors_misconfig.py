from modules.scanner.base_check import BaseCheck, CheckResult


class CorsMisconfigCheck(BaseCheck):
    name = "cors_misconfig"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        acao = headers.get("access-control-allow-origin", "") or headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("access-control-allow-credentials", "") or headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="CORS misconfiguration: wildcard origin with credentials",
                description="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true "
                            "allows any site to make authenticated requests.",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation="Remove the wildcard or do not use credentials. Use a specific origin instead.",
                cwe="CWE-942",
            ))

        if acao == "*":
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CORS: wildcard Access-Control-Allow-Origin",
                description="Any origin can read responses from this endpoint.",
                evidence=f"ACAO: {acao}",
                remediation="Restrict ACAO to specific trusted origins.",
                cwe="CWE-942",
            ))

        return results
