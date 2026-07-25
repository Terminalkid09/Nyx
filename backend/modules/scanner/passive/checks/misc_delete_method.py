import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscDeleteMethodCheck(BaseCheck):
    name = "misc_delete_method"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "GET")).upper()
        if method == "DELETE":
            path = request_data.get("path", request_data.get("url", ""))
            headers = event.get("headers", {}) or {}
            status = event.get("status")
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="DELETE method enabled",
                description=f"DELETE method is enabled at {path}. DELETE can remove server resources and must be properly authenticated.",
                evidence=f"Path: {path}\nStatus: {status}",
                remediation="Restrict DELETE method to authenticated and authorized users. Implement CSRF protection for DELETE requests.",
                cwe="CWE-749",
            ))
        return results
