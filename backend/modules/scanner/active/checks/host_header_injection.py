import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


HOST_HEADERS = [
    "evil.com",
    "evil.com:443",
    "evil.com:80",
    "evil.com%2f@",
    "evil.com:443@",
    "evil.com%00",
]


class HostHeaderInjectionCheck(BaseCheck):
    name = "active_host_header_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for host in HOST_HEADERS:
                modified = self._inject_header(base_request, "Host", host)
                try:
                    resp = await client.request(**modified)
                    if host in resp.text or host in str(resp.headers):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Host header injection detected",
                            description=f"Host header value '{host}' is reflected in the response.",
                            evidence=f"Host: {host}\nReflected in response",
                            remediation="Validate the Host header against an allowlist. Do not reflect the Host header in responses.",
                            cwe="CWE-644",
                        ))
                except Exception:
                    continue
        return results

    def _inject_header(self, base: dict, header: str, value: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["headers"] = {**req.get("headers", {}), header: value}
        return req
