import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PAYLOADS = ['%0d%0aX-Injected: true', '%0aX-Injected: true', '\\r\\nX-Injected: true']


class ActiveCrlfInjectionHeadersCheck(BaseCheck):
    name = "active_crlf_injection_headers"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for payload in PAYLOADS:
                try:
                    test_headers = dict(req.get("headers", {}))
                    test_headers["X-CRLF-Test"] = payload
                    resp = await client.get(url, headers=test_headers)
                    if resp.headers.get("x-injected", "").lower() == "true":
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="CRLF Injection in Response Headers",
                            description="CRLF sequences injected into parameters were reflected in response headers, enabling HTTP response header injection.",
                            evidence=f"Payload: {payload}\nX-Injected header found in response",
                            remediation="Validate and sanitize all input. Remove or encode CRLF characters from user input.",
                            cwe="CWE-93",
                        ))
                except Exception:
                    continue
        return results
