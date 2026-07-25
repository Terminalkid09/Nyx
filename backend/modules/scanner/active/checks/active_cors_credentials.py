import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveCorsCredentialsCheck(BaseCheck):
    name = "active_cors_credentials"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        origin = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for test_origin in ["http://evil.com", "null", "https://attacker.com"]:
                try:
                    resp = await client.options(
                        base_request.get("url", ""),
                        headers={
                            "Origin": test_origin,
                            "Access-Control-Request-Method": "GET",
                        },
                    )
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")
                    if acao and acac and acac.lower() == "true":
                        severity = "critical" if acao == "*" else "high"
                        results.append(CheckResult(
                            triggered=True,
                            severity=severity,
                            title="CORS Misconfiguration with Credentials",
                            description=f"Endpoint allows credentials with origin '{acao}'.",
                            evidence=f"Origin: {test_origin}\nACAO: {acao}\nACAC: {acac}",
                            remediation="Avoid using Access-Control-Allow-Credentials: true with wildcard origins. Specify exact origins.",
                            cwe="CWE-942",
                        ))
                except Exception:
                    continue
        return results
