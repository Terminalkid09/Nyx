import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


XPATH_PAYLOADS = [
    "' or '1'='1",
    "' and '1'='1",
    "' or 1=1--",
    "' or '1'='1' --",
    "' or 1=1 or '1'='1",
    "' or '1'='1' or '1'='1",
    "' and 1=1 and '1'='1",
    "' or '1'='1' --",
]


class XPathInjectionCheck(BaseCheck):
    name = "active_xpath_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in XPATH_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 500 or "error" in resp.text.lower() or "exception" in resp.text.lower():
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="XPath injection detected",
                                description=f"Parameter '{param}' may be vulnerable to XPath injection.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Escape XPath special characters. Use parameterised XPath queries.",
                                cwe="CWE-643",
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
