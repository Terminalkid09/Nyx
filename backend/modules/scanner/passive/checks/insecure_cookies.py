from modules.scanner.base_check import BaseCheck, CheckResult


class InsecureCookiesCheck(BaseCheck):
    name = "insecure_cookies"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        if not set_cookie:
            return results

        url = request_data.get("url", "")
        is_https = url.startswith("https://")

        cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]

        for cookie in cookies:
            cookie = cookie.strip()
            if not cookie:
                continue
            name = cookie.split("=")[0] if "=" in cookie else cookie
            lower = cookie.lower()

            if is_https and "secure" not in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title=f"Cookie '{name}' missing Secure flag on HTTPS response",
                    description="Cookie is transmitted over HTTPS but lacks the Secure flag, allowing transmission over HTTP.",
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Add the Secure flag to all cookies when served over HTTPS.",
                    cwe="CWE-614",
                ))

            is_session_patterns = ["session", "sid", "token", "auth", "login", "php", "jwt", "bearer"]
            is_session = any(p in name.lower() for p in is_session_patterns)
            if is_session and "httponly" not in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title=f"Session cookie '{name}' missing HttpOnly flag",
                    description="Session cookie is accessible via JavaScript, increasing XSS impact and session theft risk.",
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Add the HttpOnly flag to all session and authentication cookies.",
                    cwe="CWE-1004",
                ))

            if "samesite=none" in lower and "secure" not in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title=f"Cookie '{name}' has SameSite=None without Secure flag",
                    description="SameSite=None requires Secure flag, otherwise browsers reject the cookie.",
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Add the Secure flag when using SameSite=None, or use SameSite=Lax/Strict.",
                    cwe="CWE-1275",
                ))

            if "domain=" in lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title=f"Cookie '{name}' has explicit Domain attribute",
                    description="Explicit Domain attribute may broaden cookie scope to subdomains.",
                    evidence=f"Set-Cookie: {cookie}",
                    remediation="Avoid setting Domain attribute unless subdomain sharing is intentional.",
                    cwe="CWE-200",
                ))

        return results
