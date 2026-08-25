import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


BLIND_SSTI_PAYLOADS = [
    ("Jinja2", "{{7*7}}"),
    ("Jinja2", "{{config}}"),
    ("Twig", "{{7*7}}"),
    ("Freemarker", "${7*7}"),
    ("Freemarker", "${7*'7'}"),
    ("Velocity", "#set($x=7*7)$x"),
    ("Mako", "${7*7}"),
    ("Smarty", "{$smarty.now}"),
]

SSTI_SUCCESS_INDICATORS = ["49", "77", "<Config", "ConfigDict", "7*7"]


class ActiveSstiBlindCheck(BaseCheck):
    name = "active_ssti_blind"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for engine_name, payload in BLIND_SSTI_PAYLOADS:
                    modified = dict(base_request)
                    parsed = urlparse(modified["url"])
                    params = dict(parse_qsl(parsed.query))
                    params[param] = payload
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        for indicator in SSTI_SUCCESS_INDICATORS:
                            if indicator in resp.text:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title=f"Server-Side Template Injection ({engine_name})",
                                    description=f"Parameter '{param}' is vulnerable to {engine_name} SSTI.",
                                    evidence=f"Engine: {engine_name}\nPayload: {payload}\nIndicator: {indicator}",
                                    remediation="Do not render user input as templates. Use sandboxed template engines if necessary.",
                                    cwe="CWE-94",
                                ))
                                break
                    except Exception:
                        continue
        return results
