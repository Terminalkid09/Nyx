import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveCorsNullTestCheck(BaseCheck):
    name = "active_cors_null_test"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            try:
                test_headers = dict(req.get("headers", {}))
                test_headers["Origin"] = "null"
                resp = await client.get(url, headers=test_headers)
                acao = resp.headers.get("access-control-allow-origin", "")
                acc = resp.headers.get("access-control-allow-credentials", "")
                if acao == "null" and acc.lower() == "true":
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="CORS Null Origin Allowed with Credentials",
                        description="Sending Origin: null resulted in the server allowing null origin with credentials.",
                        evidence=f"ACAO: {acao}\nACC: {acc}",
                        remediation="Do not allow null origin in CORS. Use a whitelist of trusted origins. Never combine null origin with credentials.",
                        cwe="CWE-942",
                    ))
            except Exception:
                pass
        return results
