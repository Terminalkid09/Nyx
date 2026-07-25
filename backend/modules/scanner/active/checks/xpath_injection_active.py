import copy
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class XPathInjectionActiveCheck(BaseCheck):
    name = "active_xpath_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = ["'", "''", "']|//*|", "']|//user/*|", "1' and '1'='1", "1' and '1'='2", "' and 1=1 and ''='", "' and 1=2 and ''='"]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        error_patterns = [r"xpath", r"xpath.*exception", r"system.xml.xpath", r"xpath evaluation", r"namespace", r"unexpected token"]
                        for pattern in error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="XPath injection detected (booleanization)",
                                    description=f"Parameter '{param}' triggered an XPath error with payload '{payload}'.",
                                    evidence=f"Payload: {payload}\nError pattern: {pattern}",
                                    remediation="Use parameterised XPath queries or escape special characters. Avoid building XPath expressions with user input.",
                                    cwe="CWE-643",
                                ))
                                break
                    except Exception:
                        continue
        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
