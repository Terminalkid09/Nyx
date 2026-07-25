import re
from modules.scanner.base_check import BaseCheck, CheckResult


class Biz2faBypassCheck(BaseCheck):
    name = "biz_2fa_bypass"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        headers = event.get("headers", {}) or {}
        cookies = headers.get("cookie", headers.get("Cookie", ""))
        set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", ""))
        twofa_keywords = ["2fa", "twofactor", "two-factor", "mfa", "otp", "totp", "verification"]
        is_2fa_path = any(k in path.lower() for k in twofa_keywords)
        if not is_2fa_path:
            return results
        if set_cookie:
            cookies = set_cookie.split("\n") if "\n" in set_cookie else [set_cookie]
            for c in cookies:
                if "session" in c.lower() or "token" in c.lower() or "auth" in c.lower():
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="2FA bypass via session reuse",
                        description=f"2FA endpoint at '{path}' generates a session/authorization token. If the previous session is not invalidated, 2FA can be bypassed by reusing the old session.",
                        evidence=f"Path: {path}\nSet-Cookie: {c}",
                        remediation="Invalidate existing sessions when 2FA is required. Use a separate 2FA verification token that cannot be reused.",
                        cwe="CWE-287",
                    ))
                    break
        return results
