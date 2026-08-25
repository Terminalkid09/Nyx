import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ["' and '1'='1", "' and '1'='2", "'] | //*", "'] | /../*", "' or '1'='1"]
ERROR_PATTERNS = [('XPathException|XPathError|XPathParser', 'XPath injection error')]


class ActiveXpathInjectionExtCheck(BaseCheck):
    name = "active_xpath_injection_ext"

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
                                    title="Extended XPath Injection Detected",
                                    description="Parameter may be vulnerable to XPath injection via booleanization and error-based techniques.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Use parameterised XPath queries with pre-compiled expressions. Validate and sanitize all user input.",
                                    cwe="CWE-643",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Extended XPath Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Use parameterised XPath queries with pre-compiled expressions. Validate and sanitize all user input.",
                            cwe="CWE-643",
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
