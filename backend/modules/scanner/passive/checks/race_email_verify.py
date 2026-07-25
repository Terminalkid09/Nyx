import re
from modules.scanner.base_check import BaseCheck, CheckResult


class RaceEmailVerifyCheck(BaseCheck):
    name = "race_email_verify"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        email_keywords = ["verify", "email", "confirm", "activate", "registration", "signup", "register"]
        is_email_op = any(k in path.lower() for k in email_keywords)
        if is_email_op:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Race condition in email verification",
                description=f"Email verification/registration endpoint at '{path}'. Race conditions can allow duplicate account creation.",
                evidence=f"Path: {path}",
                remediation="Use unique constraints in the database. Implement idempotency tokens for registration operations.",
                cwe="CWE-362",
            ))
        return results
