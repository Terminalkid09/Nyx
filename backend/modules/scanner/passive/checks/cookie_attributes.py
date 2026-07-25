import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CookieAttributesCheck(BaseCheck):
    name = "cookie_attributes"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        set_cookie = headers_lower.get("set-cookie", "")
        if not set_cookie:
            return results

        cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
        for cookie in cookies:
            cookie = cookie.strip()
            if not cookie:
                continue
            name = cookie.split("=")[0] if "=" in cookie else cookie

            if "; secure" not in cookie.lower():
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Cookie missing Secure flag",
                    description=f"Cookie '{name}' is missing the Secure flag. It will be sent over unencrypted HTTP connections.",
                    evidence=f"Cookie: {cookie}",
                    remediation="Add the 'Secure' flag to all cookies to ensure they are only sent over HTTPS.",
                    cwe="CWE-614",
                ))

            if "; httponly" not in cookie.lower():
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Cookie missing HttpOnly flag",
                    description=f"Cookie '{name}' is missing the HttpOnly flag. It can be accessed by JavaScript.",
                    evidence=f"Cookie: {cookie}",
                    remediation="Add the 'HttpOnly' flag to cookies that do not need client-side access.",
                    cwe="CWE-1004",
                ))

            if "; samesite" not in cookie.lower():
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="Cookie missing SameSite flag",
                    description=f"Cookie '{name}' is missing the SameSite attribute. It may be sent in cross-site requests.",
                    evidence=f"Cookie: {cookie}",
                    remediation="Add SameSite=Lax or SameSite=Strict to cookies to prevent CSRF attacks.",
                    cwe="CWE-1275",
                ))
        return results
