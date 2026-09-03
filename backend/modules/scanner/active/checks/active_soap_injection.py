import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['<![CDATA[<script>]]>', ']]>', '<!--', '-->']
ERROR_PATTERNS = [('SOAP fault|SOAP-ENV|soap:Fault', 'SOAP injection error')]


class ActiveSoapInjectionCheck(BaseCheck):
    name = "active_soap_injection"

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
                                    title="SOAP XML Injection Detected",
                                    description="Parameter may be vulnerable to SOAP XML injection. XML meta-characters sent as input resulted in parsing error or unexpected behavior.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Validate and sanitize all SOAP input. Use XML parameterisation. Disable external entity resolution.",
                                    cwe="CWE-611",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="SOAP XML Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Validate and sanitize all SOAP input. Use XML parameterisation. Disable external entity resolution.",
                            cwe="CWE-611",
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
