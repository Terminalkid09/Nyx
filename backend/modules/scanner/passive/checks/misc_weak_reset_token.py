import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscWeakResetTokenCheck(BaseCheck):
    name = "misc_weak_reset_token"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        token_patterns = [
            (r"token=[a-zA-Z0-9]{1,8}(\b|[^a-zA-Z0-9])", "Short reset token (1-8 chars)"),
            (r"reset=[a-zA-Z0-9]{1,8}(\b|[^a-zA-Z0-9])", "Short reset parameter (1-8 chars)"),
            (r"code=[a-zA-Z0-9]{1,8}(\b|[^a-zA-Z0-9])", "Short code parameter (1-8 chars)"),
            (r"key=[a-zA-Z0-9]{1,8}(\b|[^a-zA-Z0-9])", "Short key parameter (1-8 chars)"),
            (r"token=\d{4,6}\b", "Numeric-only reset token (4-6 digits)"),
            (r"reset=\d{4,6}\b", "Numeric-only reset parameter"),
        ]
        for pattern, desc in token_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Weak password reset token",
                    description=f"{desc}. Weak reset tokens can be brute-forced or guessed.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Use cryptographically secure random tokens with at least 128 bits of entropy. Use a time-limited, single-use token stored server-side.",
                    cwe="CWE-331",
                ))
                break
        return results
