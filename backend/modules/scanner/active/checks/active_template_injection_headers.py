import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PAYLOADS = ['{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>']


class ActiveTemplateInjectionHeadersCheck(BaseCheck):
    name = "active_template_injection_headers"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for payload in PAYLOADS:
                try:
                    test_headers = dict(req.get("headers", {}))
                    test_headers["X-Template-Test"] = payload
                    resp = await client.get(url, headers=test_headers)
                    if payload in resp.text or "49" in resp.text:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="Template Injection in Custom Headers",
                            description="Template injection payloads sent in custom HTTP headers were evaluated by the server-side template engine.",
                            evidence=f"Payload: {payload}\nHeader: X-Template-Test",
                            remediation="Do not render user-controlled header values as templates. Validate and sanitize all header input.",
                            cwe="CWE-1336",
                        ))
                except Exception:
                    continue
        return results
