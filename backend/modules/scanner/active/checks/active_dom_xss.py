import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


DOM_XSS_SOURCES = [
    "location.hash",
    "location.search",
    "document.URL",
    "document.documentURI",
    "document.baseURI",
    "window.name",
    "document.referrer",
]


class ActiveDomXssCheck(BaseCheck):
    name = "active_dom_xss"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                modified = dict(base_request)
                parsed = urlparse(modified["url"])
                params = dict(parse_qsl(parsed.query))
                if param in params:
                    params[param] = "dom_xss_test_12345"
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        body_lower = resp.text.lower()
                        for source in DOM_XSS_SOURCES:
                            if source.lower() in body_lower:
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="Potential DOM-based XSS",
                                    description=f"Parameter '{param}' may flow into DOM XSS sink via {source}.",
                                    evidence=f"DOM source: {source}",
                                    remediation="Avoid writing user input directly to innerHTML, document.write, or eval. Use textContent or sanitizers.",
                                    cwe="CWE-79",
                                ))
                    except Exception:
                        continue
        return results
