import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method", "DELETE"),
    ("X-Method-Override", "DELETE"),
    ("X-HTTP-Method-Override", "PUT"),
    ("X-HTTP-Method-Override", "PATCH"),
]


class MethodOverrideCheck(BaseCheck):
    name = "active_method_override"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for header, method in OVERRIDE_HEADERS:
                modified = self._inject_header(base_request, header, method)
                try:
                    resp = await client.request(**modified)
                    if resp.status_code not in (405, 501, 400):
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="HTTP method override accepted",
                            description=f"Header '{header}: {method}' was accepted by the server.",
                            evidence=f"Header: {header}: {method}\nStatus: {resp.status_code}",
                            remediation="Disable HTTP method override headers if not needed.",
                            cwe="CWE-284",
                        ))
                except Exception:
                    continue
        return results

    def _inject_header(self, base: dict, header: str, value: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["headers"] = {**req.get("headers", {}), header: value}
        return req
