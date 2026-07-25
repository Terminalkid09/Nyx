import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


CONTENT_TYPES = [
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "application/json",
    "text/javascript",
    "application/javascript",
    "text/xml",
    "application/xml",
]


class ContentTypeSniffCheck(BaseCheck):
    name = "active_content_type_sniff"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for ctype in CONTENT_TYPES:
                modified = self._inject_header(base_request, "Content-Type", ctype)
                try:
                    resp = await client.request(**modified)
                    resp_ct = resp.headers.get("content-type", "")
                    if ctype in resp_ct:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Content-Type sniffing possible",
                            description=f"Server accepted Content-Type '{ctype}' and reflected it in response.",
                            evidence=f"Sent: {ctype}\nReceived: {resp_ct}",
                            remediation="Set X-Content-Type-Options: nosniff. Validate Content-Type strictly.",
                            cwe="CWE-430",
                        ))
                except Exception:
                    continue
        return results

    def _inject_header(self, base: dict, header: str, value: str) -> dict:
        import copy
        req = copy.deepcopy(base)
        req["headers"] = {**req.get("headers", {}), header: value}
        return req
