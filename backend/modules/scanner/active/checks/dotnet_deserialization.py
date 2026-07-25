import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


DOTNET_PAYLOADS = [
    {"__VIEWSTATE": "/wEPDwUKMTYyNzkwNTI5NGRk"},
    {"__VIEWSTATE": "/wEPDwUKMTYyNzkwNTI5NWRk"},
    {"__EVENTVALIDATION": "/wEdAAQAAQABAAEAAQ=="},
]


class DotnetDeserializationCheck(BaseCheck):
    name = "active_dotnet_deserialization"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload in DOTNET_PAYLOADS:
                modified = self._inject_body(base_request, payload)
                try:
                    resp = await client.request(**modified)
                    if "machine key" in resp.text.lower() or "validation" in resp.text.lower() or "viewstate" in resp.text.lower():
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title=".NET deserialization vulnerability detected",
                            description="Server processed .NET ViewState data. May be vulnerable to deserialization attacks.",
                            evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                            remediation="Enable ViewState MAC validation. Use encryption for sensitive ViewState data.",
                            cwe="CWE-502",
                        ))
                except Exception:
                    continue
        return results

    def _inject_body(self, base: dict, payload: dict) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["data"] = payload
        return req
