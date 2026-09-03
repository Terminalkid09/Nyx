import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${{7*7}}", "49"),
    ("{{config}}", "Config"),
    ("{{self._TemplateReference__context}}", "cycler"),
]


class SstiInjectionCheck(BaseCheck):
    name = "active_ssti_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload, indicator in SSTI_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if indicator in resp.text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="SSTI injection detected",
                                description=f"Parameter '{param}' evaluates template expressions.",
                                evidence=f"Payload: {payload}\nIndicator: {indicator}",
                                remediation="Do not render user input as templates. Use sandboxed template engines.",
                                cwe="CWE-1336",
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
