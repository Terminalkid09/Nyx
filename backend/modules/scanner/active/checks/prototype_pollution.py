import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PP_PAYLOADS = [
    ("__proto__[test]=true", "__proto__"),
    ("constructor[prototype][test]=true", "constructor.prototype"),
    ("__proto__.test=evil", "__proto__"),
    ("constructor.prototype.test=evil", "constructor.prototype"),
]


class PrototypePollutionCheck(BaseCheck):
    name = "active_prototype_pollution"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload, indicator in PP_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200 and "test" in resp.text.lower():
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Prototype pollution detected",
                                description=f"Parameter '{param}' may be vulnerable to prototype pollution.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Validate JSON input against a strict schema. Avoid recursive merge operations.",
                                cwe="CWE-1321",
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
