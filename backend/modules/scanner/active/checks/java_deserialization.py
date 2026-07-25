import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


JAVA_DESER_PAYLOADS = [
    "aced0005737200116a6176612e7574696c2e486173684d61700507dac1c31660d103000246000a6c6f6164466163746f724900097468726573686f6c6478703f4000000000000c77080000001000000001",
    "rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAABeA==",
]


class JavaDeserializationCheck(BaseCheck):
    name = "active_java_deserialization"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload in JAVA_DESER_PAYLOADS:
                modified = self._inject_body(base_request, payload)
                try:
                    resp = await client.request(**modified)
                    if resp.status_code == 500 or "Exception" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="Java deserialization vulnerability detected",
                            description="Server processed Java serialized data and returned an error. May be vulnerable to deserialization attacks.",
                            evidence=f"Payload: {payload[:100]}...\nStatus: {resp.status_code}",
                            remediation="Do not deserialize untrusted Java objects. Use safe serialization formats.",
                            cwe="CWE-502",
                        ))
                except Exception:
                    continue
        return results

    def _inject_body(self, base: dict, payload: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        import base64
        try:
            req["content"] = bytes.fromhex(payload)
        except (ValueError, AttributeError):
            req["content"] = base64.b64decode(payload)
        req["headers"] = {**req.get("headers", {}), "Content-Type": "application/x-java-serialized-object"}
        return req
