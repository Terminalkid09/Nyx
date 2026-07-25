import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PAYLOADS = [
    '{"__proto__": {"polluted": true}}',
    '{"constructor": {"prototype": {"polluted": true}}}',
]


class ActivePrototypePollutionJsonCheck(BaseCheck):
    name = "active_prototype_pollution_json"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            headers = dict(req.get("headers", {}))
            headers["Content-Type"] = "application/json"
            for payload in PAYLOADS:
                try:
                    resp = await client.post(url, content=payload, headers=headers)
                    if resp.status_code < 500:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Server-Side Prototype Pollution via JSON.parse",
                            description="JSON payload containing __proto__ or constructor.prototype was accepted by the server without rejection, indicating potential prototype pollution.",
                            evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                            remediation="Use JSON.parse with reviver to filter dangerous keys. Validate and sanitize JSON input. Use Maps instead of plain objects.",
                            cwe="CWE-1321",
                        ))
                except Exception:
                    continue
        return results
