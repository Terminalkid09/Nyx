import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['${7*7}', '#{7*7}', '${"".getClass()}', '#{session}', '${request.getParameter("test")}', '${session.getAttribute("user")}']
ERROR_PATTERNS = [('49|java\\.lang\\.|javax\\.el\\.|ExpressionException', 'EL injection indicator')]


class ActiveElInjectionAdvancedCheck(BaseCheck):
    name = "active_el_injection_advanced"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload in PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        for pattern, desc in ERROR_PATTERNS:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="Advanced Expression Language Injection Detected",
                                    description="Parameter may be vulnerable to advanced EL injection. Extended EL payloads resulted in expression evaluation.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Disable EL evaluation on user input. Use template engines that auto-escape. Validate and sanitize all input.",
                                    cwe="CWE-917",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="Advanced Expression Language Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Disable EL evaluation on user input. Use template engines that auto-escape. Validate and sanitize all input.",
                            cwe="CWE-917",
                        ))
                    except Exception:
                        continue

        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
