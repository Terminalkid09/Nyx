from modules.scanner.base_check import BaseCheck, CheckResult


class CookieFlagsCheck(BaseCheck):
    name = "cookie_flags"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        if not set_cookie:
            return results

        cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
        for cookie in cookies:
            name = cookie.split("=")[0] if "=" in cookie else cookie
            lower = cookie.lower()
            if "secure" not in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title=f"Cookie '{name}' missing Secure flag",
                    description="Cookie can be transmitted over unencrypted HTTP connections.",
                    evidence=f"Set-Cookie: {cookie.strip()}",
                    remediation="Add the Secure flag to cookies.",
                    cwe="CWE-614",
                ))
            if "httponly" not in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    description="Cookie is accessible via JavaScript, increasing XSS impact.",
                    evidence=f"Set-Cookie: {cookie.strip()}",
                    remediation="Add the HttpOnly flag to cookies not needed by JS.",
                    cwe="CWE-1004",
                ))
            if "samesite" not in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title=f"Cookie '{name}' missing SameSite attribute",
                    description="CSRF protection may be weaker without SameSite.",
                    evidence=f"Set-Cookie: {cookie.strip()}",
                    remediation="Add SameSite=Lax or SameSite=Strict to cookies.",
                    cwe="CWE-1275",
                ))
        return results
