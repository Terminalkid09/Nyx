import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


CORS_ORIGINS = [
    "https://evil.com",
    "https://evil.com.evil.com",
    "null",
    "https://evil.com",
    "https://evil.com:443",
    "http://evil.com",
]


class CorsWildcardCheck(BaseCheck):
    name = "active_cors_wildcard"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for origin in CORS_ORIGINS:
                modified = self._inject_header(base_request, "Origin", origin)
                try:
                    resp = await client.request(**modified)
                    acao = resp.headers.get("access-control-allow-origin", "") or resp.headers.get("Access-Control-Allow-Origin", "")
                    if acao == origin or acao == "*":
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="CORS misconfiguration detected",
                            description=f"Origin '{origin}' is allowed by CORS. This may allow cross-origin data theft.",
                            evidence=f"Origin: {origin}\nACAO: {acao}",
                            remediation="Restrict Access-Control-Allow-Origin to specific trusted origins.",
                            cwe="CWE-942",
                        ))
                except Exception:
                    continue
        return results

    def _inject_header(self, base: dict, header: str, value: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["headers"] = {**req.get("headers", {}), header: value}
        return req
