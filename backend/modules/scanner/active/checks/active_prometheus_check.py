import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActivePrometheusCheck(BaseCheck):
    name = "active_prometheus_check"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            paths = ["/metrics", "/prometheus", "/actuator/prometheus", "/api/v1/query?query=up", "/federate"]
            for path in paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    text = resp.text[:500]
                    if any(kw in text for kw in ["go_goroutines", "process_cpu_seconds", "http_requests_total", "promhttp", "# HELP"]):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Prometheus Metrics Exposed",
                            description=f"Prometheus metrics endpoint found at '{path}'.",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}",
                            remediation="Restrict /metrics endpoint to internal networks. Use authentication. Disable if not needed.",
                            cwe="CWE-200",
                        ))
                except Exception:
                    continue
        return results
