import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/redirect",
    "//evil.com/redirect",
    "https://evil.com%2f@",
    "https://evil.com:443@",
]


class OpenRedirectCheck(BaseCheck):
    name = "active_open_redirect"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in REDIRECT_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified, follow_redirects=False)
                        location = resp.headers.get("location", "") or resp.headers.get("Location", "")
                        if location and "evil" in location.lower():
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Open redirect detected",
                                description=f"Parameter '{param}' causes redirect to attacker-controlled domain.",
                                evidence=f"Payload: {payload}\nLocation: {location}",
                                remediation="Validate and whitelist redirect destinations.",
                                cwe="CWE-601",
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
