import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthRememberMeCheck(BaseCheck):
    name = "auth_remember_me"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        if not set_cookie:
            return results
        cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
        for cookie in cookies:
            lower = cookie.lower()
            if "remember" in lower or "rememberme" in lower or "persist" in lower:
                if "httponly" not in lower:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="Remember me token insecurely stored",
                        description="Persistent 'remember me' cookie lacks HttpOnly flag, allowing JavaScript access to the token.",
                        evidence=f"Cookie: {cookie}",
                        remediation="Add HttpOnly and Secure flags to remember-me cookies. Use a randomly generated token instead of username-based.",
                        cwe="CWE-614",
                    ))
                if "secure" not in lower:
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="Remember me cookie missing Secure flag",
                        description="Persistent cookie lacking Secure flag may be transmitted over HTTP.",
                        evidence=f"Cookie: {cookie}",
                        remediation="Add the Secure flag to all remember-me cookies.",
                        cwe="CWE-614",
                    ))
        return results
