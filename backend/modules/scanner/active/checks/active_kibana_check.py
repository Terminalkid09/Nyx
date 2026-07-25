import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveKibanaCheck(BaseCheck):
    name = "active_kibana_check"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            paths = ["/kibana/", "/kibana/api/status", "/elasticsearch/", "/es/", "/elastic/"]
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if "kibana" in resp.text.lower() or resp.headers.get("kbn-name", "") or "cluster_name" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Kibana/Elasticsearch Exposed",
                            description=f"Kibana or Elasticsearch detected at '{path}'.",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}",
                            remediation="Restrict Kibana/ES to internal networks. Enable authentication and TLS. Use reverse proxy with access control.",
                            cwe="CWE-200",
                        ))
                except Exception:
                    continue
        return results
