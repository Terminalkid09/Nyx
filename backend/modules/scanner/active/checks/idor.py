import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class IdorCheck(BaseCheck):
    name = "active_idor"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        numeric_params = [p for p in target_params if self._is_numeric_param(base_request, p)]
        if not numeric_params:
            return results

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in numeric_params:
                try:
                    original = await client.request(**base_request)
                    original_size = len(original.content)

                    increments = [1, 2, 10, 100, 1000, 9999, 100000]
                    for inc in increments:
                        modified = self._inject_int(base_request, param, inc)
                        resp = await client.request(**modified)
                        if resp.status_code == 200 and len(resp.content) != original_size:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Potential IDOR detected",
                                description=f"Parameter '{param}' returns different data with modified value ({inc}).",
                                evidence=f"Modified value: {inc}\nOriginal size: {original_size}, New size: {len(resp.content)}",
                                remediation="Implement proper access control checks. Do not rely on hidden or obfuscated IDs.",
                                cwe="CWE-639",
                            ))
                            break
                except Exception:
                    continue
        return results

    def _is_numeric_param(self, base: dict, param: str) -> bool:
        import urllib.parse
        parsed = urllib.parse.urlparse(base["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        return params.get(param, "").isdigit()

    def _inject_int(self, base: dict, param: str, value: int) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if param in params:
            params[param] = str(value)
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
