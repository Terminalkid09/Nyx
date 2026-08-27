import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['<?xml version="1.0"?><xsl:stylesheet version="1.0"><xsl:template match="/"><xsl:value-of select="system-property(\'os.name\')"/></xsl:template></xsl:stylesheet>']
ERROR_PATTERNS = [('XSLTError|XsltTransformError|XSL transform', 'XSLT injection error')]


class ActiveXsltInjectionCheck(BaseCheck):
    name = "active_xslt_injection"

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
                                    title="XSLT Injection Detected",
                                    description="Parameter may be vulnerable to XSLT injection. XSLT transformation payloads resulted in error or unexpected behavior.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Disable XSLT processing of user-supplied stylesheets. Use a fixed, trusted stylesheet. Validate input.",
                                    cwe="CWE-91",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="XSLT Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Disable XSLT processing of user-supplied stylesheets. Use a fixed, trusted stylesheet. Validate input.",
                            cwe="CWE-91",
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
