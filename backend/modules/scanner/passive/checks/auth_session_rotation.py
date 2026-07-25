import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthSessionRotationCheck(BaseCheck):
    name = "auth_session_rotation"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        set_cookie = headers.get("set-cookie", "") or headers.get("Set-Cookie", "")
        path = request_data.get("path", request_data.get("url", "")).lower()
        if not set_cookie or "login" not in path and "signin" not in path:
            return results
        cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
        for cookie in cookies:
            lower = cookie.lower()
            name = cookie.split("=")[0] if "=" in cookie else ""
            session_keywords = ["session", "sid", "token", "auth", "jwt"]
            if any(k in name.lower() for k in session_keywords):
                results.append(CheckResult(
                    triggered=True,
                    severity="info",
                    title="Session token set on login",
                    description="A session cookie is set after login. Verify that the old session is invalidated (session rotation).",
                    evidence=f"Cookie: {cookie}\nPath: {path}",
                    remediation="Ensure session tokens are rotated on login to prevent session fixation attacks.",
                    cwe="CWE-384",
                ))
        return results
