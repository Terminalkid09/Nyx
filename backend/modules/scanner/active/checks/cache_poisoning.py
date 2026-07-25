import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


CACHE_POISON_HEADERS = [
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Original-URL", "/../admin"),
    ("X-Rewrite-URL", "/../admin"),
    ("X-Original-URL", "/admin/"),
    ("X-Rewrite-URL", "/admin/"),
]


class CachePoisoningCheck(BaseCheck):
    name = "active_cache_poisoning"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for header, value in CACHE_POISON_HEADERS:
                modified = self._inject_header(base_request, header, value)
                try:
                    resp = await client.request(**modified)
                    if resp.status_code == 200 and resp.status_code != 404:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Cache poisoning detected",
                            description=f"Header '{header}: {value}' was accepted. May be used for cache poisoning.",
                            evidence=f"Header: {header}: {value}\nStatus: {resp.status_code}",
                            remediation="Do not use unvalidated headers in cache key computation.",
                            cwe="CWE-444",
                        ))
                except Exception:
                    continue
        return results

    def _inject_header(self, base: dict, header: str, value: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["headers"] = {**req.get("headers", {}), header: value}
        return req
