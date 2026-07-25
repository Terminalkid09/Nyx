import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveGrafanaCheck(BaseCheck):
    name = "active_grafana_check"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            paths = ["/grafana/", "/grafana/api/health", "/grafana/login", "/graphana/", "/monitoring/"]
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if "grafana" in resp.text.lower() or resp.headers.get("x-grafana-version", ""):
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Grafana Dashboard Exposed",
                            description=f"Grafana instance detected at '{path}'.",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}",
                            remediation="Restrict Grafana to internal networks. Enable authentication. Use reverse proxy with access control.",
                            cwe="CWE-200",
                        ))
                except Exception:
                    continue
        return results
