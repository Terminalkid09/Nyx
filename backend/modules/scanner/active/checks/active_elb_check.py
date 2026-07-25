import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveElbCheck(BaseCheck):
    name = "active_elb_check"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            paths = ["/api/health", "/health", "/status", "/elb-status", "/api/status", "/_health"]
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}", headers={"User-Agent": "ELB-HealthChecker/2.0"})
                    if resp.status_code == 200 and any(x in resp.text.lower() for x in ["ok", "healthy", "alive", "true"]):
                        results.append(CheckResult(
                            triggered=True,
                            severity="low",
                            title="Health/Status Endpoint Exposed",
                            description=f"Health check endpoint found at '{path}'.",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}",
                            remediation="Restrict health endpoints to internal networks or monitor via authentication.",
                            cwe="CWE-200",
                        ))
                except Exception:
                    continue
        return results
