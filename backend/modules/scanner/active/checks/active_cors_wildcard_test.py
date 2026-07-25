import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveCorsWildcardTestCheck(BaseCheck):
    name = "active_cors_wildcard_test"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            try:
                test_headers = dict(req.get("headers", {}))
                test_headers["Origin"] = "https://evil.com"
                resp = await client.get(url, headers=test_headers)
                acao = resp.headers.get("access-control-allow-origin", "")
                acc = resp.headers.get("access-control-allow-credentials", "")
                if acao == "https://evil.com" and acc.lower() == "true":
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="CORS Wildcard Origin Reflection with Credentials",
                        description="Sending Origin: https://evil.com resulted in the server reflecting this origin with Access-Control-Allow-Credentials: true.",
                        evidence=f"Origin sent: https://evil.com\nACAO: {acao}\nACC: {acc}",
                        remediation="Do not reflect Origin headers in Access-Control-Allow-Origin. Use a whitelist of trusted origins.",
                        cwe="CWE-942",
                    ))
            except Exception:
                pass
        return results
