import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscResetTokenEmailCheck(BaseCheck):
    name = "misc_reset_token_email"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"reset.*token[^<]*</a>", "Password reset token in HTML link"),
            (r"reset.*link[^<]*</a>", "Password reset link in anchor"),
            (r"reset_token[=:]\s*[a-zA-Z0-9_\-]{10,}", "Reset token parameter in body"),
            (r"forgot.*token[=:]\s*[a-zA-Z0-9_\-]{10,}", "Forgot password token in body"),
            (r"recover.*token[=:]\s*[a-zA-Z0-9_\-]{10,}", "Recover token in body"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Password reset token in email body",
                    description=f"{desc}. Password reset tokens embedded in email content (as opposed to links) may be logged or intercepted.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:300]}",
                    remediation="Send password reset tokens as part of a URL link, not as plain text in the email body. Use time-limited tokens.",
                    cwe="CWE-200",
                ))
                break
        return results
