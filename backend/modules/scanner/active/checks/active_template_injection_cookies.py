import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PAYLOADS = ['{{7*7}}', '${7*7}', '#{7*7}']


class ActiveTemplateInjectionCookiesCheck(BaseCheck):
    name = "active_template_injection_cookies"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for payload in PAYLOADS:
                try:
                    test_headers = dict(req.get("headers", {}))
                    test_headers["Cookie"] = f"template_test={payload}"
                    resp = await client.get(url, headers=test_headers)
                    if payload in resp.text or "49" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="Template Injection in Cookie Headers",
                            description="Template injection payloads sent in Cookie headers were evaluated by the server-side template engine.",
                            evidence=f"Payload: {payload}\nCookie: template_test={payload}",
                            remediation="Do not render user-controlled cookie values as templates. Validate and sanitize cookie input.",
                            cwe="CWE-1336",
                        ))
                except Exception:
                    continue
        return results
