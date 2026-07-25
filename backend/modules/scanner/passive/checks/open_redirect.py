import re
from urllib.parse import urlparse, urlencode, parse_qs
from modules.scanner.base_check import BaseCheck, CheckResult


class OpenRedirectCheck(BaseCheck):
    name = "open_redirect"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        status = event.get("status")
        headers = event.get("headers", {}) or {}
        location = headers.get("location", "") or headers.get("Location", "")

        if status in (301, 302, 303, 307, 308) and location:
            parsed = urlparse(location)
            request_host = (request_data.get("host") or "").lower()
            if parsed.netloc and parsed.netloc.lower() != request_host:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Open redirect detected",
                    description=f"Redirect to external domain: {parsed.netloc}",
                    evidence=f"Location: {location}",
                    remediation="Validate and whitelist redirect destinations. Avoid user-controlled redirect targets.",
                    cwe="CWE-601",
                ))

        url = event.get("url", "") or request_data.get("url", "")
        redirect_params = ["redirect", "url", "next", "return", "return_to", "return_url", "target", "dest", "destination", "out", "view", "dir", "file", "load", "path", "continue", "window", "open", "callback", "referer", "reference", "src", "nav", "page", "host", "port", "domain"]
        for param in redirect_params:
            pattern = rf"[?&]{param}=https?://"
            if re.search(pattern, url, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Potential open redirect parameter detected",
                    description=f"URL parameter '{param}' contains a URL pointing to an external domain. This may be used for open redirect attacks.",
                    evidence=f"Parameter: {param}\nURL: {url}",
                    remediation="Validate and whitelist redirect destinations. Do not allow arbitrary URLs in redirect parameters.",
                    cwe="CWE-601",
                ))
                break
        return results
