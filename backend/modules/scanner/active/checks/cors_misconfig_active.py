import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://evil.com.evil.com",
    "https://evil.com.evil.com:8080",
    "https://attacker.com",
    "https://evil.com:443",
    "http://evil.com",
    "https://evil.com/",
]


class CorsMisconfigActiveCheck(BaseCheck):
    name = "cors_misconfig_active"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for origin in TEST_ORIGINS:
                modified = copy.deepcopy(base_request)
                headers = dict(modified.get("headers", {}))
                headers["Origin"] = origin
                modified["headers"] = headers

                try:
                    resp = await client.request(**modified)
                    acao = resp.headers.get("access-control-allow-origin", "")
                    acac = resp.headers.get("access-control-allow-credentials", "")
                    acam = resp.headers.get("access-control-allow-methods", "")

                    if acao == origin or acao == "*":
                        if acac and acac.lower() == "true":
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title=f"CORS misconfiguration: Origin reflection with credentials",
                                description=f"Origin '{origin}' is reflected in ACAO with credentials allowed.",
                                evidence=f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                                remediation="Do not reflect arbitrary origins with Access-Control-Allow-Credentials: true. "
                                            "Use a whitelist of trusted origins.",
                                cwe="CWE-942",
                            ))
                        elif acao == origin:
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title=f"CORS misconfiguration: Origin '{origin}' is reflected",
                                description=f"The Origin header '{origin}' is reflected in Access-Control-Allow-Origin.",
                                evidence=f"Origin: {origin}\nACAO: {acao}\nACAM: {acam}",
                                remediation="Whitelist specific origins instead of reflecting the Origin header.",
                                cwe="CWE-942",
                            ))
                except Exception:
                    continue

        return results
