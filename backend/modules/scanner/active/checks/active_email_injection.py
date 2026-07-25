import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


EMAIL_INJECTION_PAYLOADS = [
    "test@example.com\nCC: victim@example.com",
    "test@example.com\r\nBCC: thousands@example.com",
    '"test@example.com" <test@example.com>',
    "test@example.com%0A%0DCC:%20attacker@example.com",
]


class ActiveEmailInjectionCheck(BaseCheck):
    name = "active_email_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for payload in EMAIL_INJECTION_PAYLOADS:
                modified = dict(base_request)
                parsed = urlparse(modified["url"])
                params = dict(parse_qsl(parsed.query))
                for param in target_params:
                    if param in params:
                        params[param] = payload
                        modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                        try:
                            resp = await client.request(**modified)
                            if resp.status_code in (200, 302, 303):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="Email Header Injection",
                                    description=f"Parameter '{param}' may be vulnerable to email header injection.",
                                    evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                    remediation="Sanitize email inputs. Remove newline characters from email headers. Use well-tested email libraries.",
                                    cwe="CWE-93",
                                ))
                        except Exception:
                            continue
        return results
