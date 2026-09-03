import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


CSP_BYPASS_PAYLOADS = [
    ("JSONP callback", "/?callback=alert(1)"),
    ("Angular sandbox escape", "/#?constructor.constructor('alert(1)')()"),
    ("Script src injection", "/?__proto__[onload]=alert(1)"),
]


class ActiveCspBypassCheck(BaseCheck):
    name = "active_csp_bypass"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for bypass_name, payload in CSP_BYPASS_PAYLOADS:
                    modified = dict(base_request)
                    parsed = urlparse(modified["url"])
                    params = dict(parse_qsl(parsed.query))
                    params[param] = payload
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        if payload in resp.text and "text/html" in resp.headers.get("content-type", ""):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title=f"CSP Bypass via {bypass_name}",
                                description=f"Parameter '{param}' may allow CSP bypass.",
                                evidence=f"Payload: {payload}",
                                remediation="Review CSP policy. Avoid using unsafe-inline, unsafe-eval. Implement strict-dynamic.",
                                cwe="CWE-1021",
                            ))
                    except Exception:
                        continue
        return results
