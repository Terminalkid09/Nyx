import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class HttpParamPollutionCheck(BaseCheck):
    name = "active_http_param_pollution"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                modified = self._inject_duplicate(base_request, param)
                try:
                    resp = await client.request(**modified)
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="HTTP parameter pollution detected",
                        description=f"Parameter '{param}' was sent twice. Server accepted duplicate parameters.",
                        evidence=f"Parameter: {param}\nStatus: {resp.status_code}",
                        remediation="Use the first or last value consistently. Reject duplicate parameters if not expected.",
                        cwe="CWE-235",
                    ))
                except Exception:
                    continue
        return results

    def _inject_duplicate(self, base: dict, param: str) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = urllib.parse.parse_qsl(parsed.query)
        params.append((param, params[0][1] if params else "test"))
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
