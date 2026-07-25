import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthLoginOverHttpCheck(BaseCheck):
    name = "auth_login_over_http"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        path = request_data.get("path", "") or ""
        if url.startswith("http://") and ("login" in path.lower() or "signin" in path.lower() or "auth" in path.lower()):
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Login form over HTTP",
                description=f"Login page at {url} is served over unencrypted HTTP, allowing credential interception.",
                evidence=f"URL: {url}",
                remediation="Enforce HTTPS for all login and authentication pages. Use HSTS to prevent downgrade attacks.",
                cwe="CWE-319",
            ))
        return results
