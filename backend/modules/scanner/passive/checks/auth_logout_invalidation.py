import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthLogoutInvalidationCheck(BaseCheck):
    name = "auth_logout_invalidation"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", "")).lower()
        method = request_data.get("method", event.get("method", "GET")).upper()
        headers = event.get("headers", {}) or {}
        set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        if "logout" not in path and "signout" not in path and "endsession" not in path:
            return results
        if set_cookie:
            cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
            for cookie in cookies:
                lower = cookie.lower()
                if "max-age=0" in lower or "expires=thu, 01" in lower or "expires=thu, 01 jan 1970" in lower:
                    results.append(CheckResult(
                        triggered=True,
                        severity="info",
                        title="Session cookie cleared on logout",
                        description=f"Logout endpoint at {path} clears the session cookie, indicating session invalidation.",
                        evidence=f"Cookie: {cookie}\nPath: {path}",
                        remediation="This is good practice. Ensure the server-side session is also invalidated, not just the client cookie.",
                        cwe="CWE-613",
                    ))
                    return results
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Logout does not invalidate session cookie",
                description=f"Logout endpoint at {path} does not clear the session cookie, leaving the session active.",
                evidence=f"Path: {path}\nSet-Cookie: {set_cookie}",
                remediation="Clear the session cookie on logout by setting Max-Age=0 or an expired date.",
                cwe="CWE-613",
            ))
        return results
