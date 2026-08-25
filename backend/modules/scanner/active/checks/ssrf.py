import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

SSRF_PAYLOADS = [
    "http://127.0.0.1:22",
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://localhost",
    "http://0.0.0.0:22",
    "http://[::1]:22",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "file:///etc/passwd",
]

SSRF_INDICATORS = [
    "root:x:0:0:",
    "OpenSSH",
    "HTTP/1.1 400",
    "meta-data",
    "ami-id",
]


class SsrfCheck(BaseCheck):
    name = "active_ssrf"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in SSRF_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        for indicator in SSRF_INDICATORS:
                            if indicator in resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="SSRF detected",
                                    description=f"Parameter '{param}' fetches internal resources.",
                                    evidence=f"Payload: {payload}\nIndicator: {indicator}",
                                    remediation="Validate and restrict URL parameters. Block private IP ranges. Use an allowlist.",
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
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
