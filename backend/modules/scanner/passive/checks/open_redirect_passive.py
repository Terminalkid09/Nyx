from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class OpenRedirectPassiveCheck(BaseCheck):
    name = "open_redirect_passive"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        status = event.get("status")
        headers = event.get("headers", {}) or {}

        if status in (301, 302, 303, 307, 308):
            location = headers.get("location", "") or headers.get("Location", "")
            if location and location.startswith("http"):
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

        return results
