import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthAccountLockoutCheck(BaseCheck):
    name = "auth_account_lockout"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        if not body:
            return results
        lockout_patterns = [
            r"account.*locked",
            r"account.*temporarily.*suspend",
            r"too many.*attempts",
            r"too many.*login",
            r"try again later",
            r"account.*blocked",
            r"maximum.*attempts",
            r"brute.*force.*detected",
        ]
        has_lockout = any(re.search(p, body, re.IGNORECASE) for p in lockout_patterns)
        if has_lockout:
            results.append(CheckResult(
                triggered=True,
                severity="info",
                title="Account lockout detection present",
                description="The application appears to have account lockout mechanisms for failed login attempts.",
                evidence=f"Lockout message found in response body",
                remediation="Ensure lockout thresholds are reasonable and lockout duration is appropriate. This is informational.",
                cwe="CWE-307",
            ))
        else:
            path = request_data.get("path", request_data.get("url", ""))
            is_login = any(p in path.lower() for p in ["login", "signin", "auth", "authenticate"])
            if is_login:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Missing account lockout mechanism",
                    description="Login endpoint response does not indicate any account lockout mechanism, which may allow brute force attacks.",
                    evidence=f"Path: {path}\nNo lockout indicators found",
                    remediation="Implement account lockout after a configurable number of failed login attempts.",
                    cwe="CWE-307",
                ))
        return results
