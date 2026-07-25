import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


CACHE_POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-Host", "evil.com"),
]


class WebCachePoisonCheck(BaseCheck):
    name = "active_web_cache_poison"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for header, value in CACHE_POISON_HEADERS:
                modified = self._inject_header(base_request, header, value)
                try:
                    resp = await client.request(**modified)
                    if value in resp.text or value in str(resp.headers):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Web cache poisoning detected",
                            description=f"Header '{header}' value is reflected in the response. This can be used for cache poisoning.",
                            evidence=f"Header: {header}: {value}\nReflected in response",
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
