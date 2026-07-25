import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ["' or '1'='1", "']|//*", "' and 1=1 and ''='"]
ERROR_PATTERNS = [('XPathException|XPathError', 'XPath injection via headers')]


class ActiveXpathHeadersCheck(BaseCheck):
    name = "active_xpath_headers"

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
                                    title="XPath Injection in Custom Headers",
                                    description="XPath injection payloads sent in custom HTTP headers resulted in errors or unexpected behavior.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Use parameterised XPath. Validate and sanitize all header input. Encode special characters.",
                                    cwe="CWE-643",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="XPath Injection in Custom Headers (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Use parameterised XPath. Validate and sanitize all header input. Encode special characters.",
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
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
