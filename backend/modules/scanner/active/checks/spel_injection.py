import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


SPEL_PAYLOADS = [
    ("#{7*7}", "49"),
    ("#{9999999+1}", "10000000"),
    ("#{T(java.lang.Runtime).getRuntime()}", "Runtime"),
    ("#{T(java.lang.System).getProperty('user.dir')}", "user.dir"),
    ("#{T(java.lang.Math).abs(-1)}", "1"),
]


class SpelInjectionCheck(BaseCheck):
    name = "active_spel_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload, indicator in SPEL_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if indicator in resp.text:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="SpEL injection detected",
                                description=f"Parameter '{param}' evaluates Spring Expression Language expressions.",
                                evidence=f"Payload: {payload}\nIndicator: {indicator}",
                                remediation="Do not evaluate user input as SpEL expressions. Use SimpleEvaluationContext.",
                                cwe="CWE-917",
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
