import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


class ActiveHeaderInjectionCheck(BaseCheck):
    name = "active_header_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                modified = dict(base_request)
                parsed = urlparse(modified["url"])
                params = dict(parse_qsl(parsed.query))
                if param in params:
                    params[param] = "test%0d%0aX-Injected:%20true"
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        if "X-Injected" in str(resp.headers):
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="HTTP Header Injection",
                                description=f"Parameter '{param}' allows CRLF injection into response headers.",
                                evidence=f"Payload: test\\r\\nX-Injected: true\nInjected header found in response.",
                                remediation="Encode or strip CRLF characters from user input before including in headers.",
                                cwe="CWE-113",
                            ))
                    except Exception:
                        continue
        return results
