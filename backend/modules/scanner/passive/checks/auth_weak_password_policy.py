import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthWeakPasswordPolicyCheck(BaseCheck):
    name = "auth_weak_password_policy"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        weak_hints = [
            (r"password must be at least \d{1} characters", "Only 1 character minimum hint"),
            (r"password cannot be empty", "Password can be any length"),
            (r"password must be \d{1} characters", "Very short minimum length hint"),
            (r"no special characters needed", "No special characters required hint"),
            (r"no numbers needed", "No numbers required hint"),
            (r"password cannot be your username", "Only basic requirement hint"),
        ]
        for pattern, desc in weak_hints:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Weak password policy hint",
                    description=f"{desc} found. Weak password requirements make accounts vulnerable to brute force.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:300]}",
                    remediation="Enforce a strong password policy: minimum 8 characters, mix of uppercase, lowercase, numbers, and special characters.",
                    cwe="CWE-521",
                ))
                break
        return results
