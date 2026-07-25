import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscPatchMethodCheck(BaseCheck):
    name = "misc_patch_method"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "GET")).upper()
        if method == "PATCH":
            path = request_data.get("path", request_data.get("url", ""))
            headers = event.get("headers", {}) or {}
            status = event.get("status")
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="PATCH method enabled",
                description=f"PATCH method is enabled at {path}. PATCH modifies resources and should be properly authorized.",
                evidence=f"Path: {path}\nStatus: {status}",
                remediation="Ensure PATCH requests are properly authenticated and authorized. Validate partial updates to prevent mass assignment.",
                cwe="CWE-749",
            ))
        return results
