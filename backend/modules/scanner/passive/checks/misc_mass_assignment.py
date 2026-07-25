import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscMassAssignmentCheck(BaseCheck):
    name = "misc_mass_assignment"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        sensitive_params = ["role", "admin", "is_admin", "is_verified", "is_active", "is_superuser", "account_type", "permissions", "group", "user_type", "access_level", "privilege", "is_premium", "is_verified", "is_staff"]
        body_lower = body.lower()
        found_params = [p for p in sensitive_params if f'"{p}"' in body_lower or f'{p}=' in body_lower or f'{p}:' in body_lower]
        if found_params:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Mass assignment vulnerabilities",
                description=f"Sensitive parameters '{', '.join(found_params)}' found in request body. These can be used for mass assignment attacks if not protected.",
                evidence=f"Parameters found: {found_params}\nBody: {body[:500]}",
                remediation="Use DTOs (Data Transfer Objects) or whitelist allowed parameters. Never directly bind request body to model objects.",
                cwe="CWE-915",
            ))
        return results
