import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscPutMethodCheck(BaseCheck):
    name = "misc_put_method"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "GET")).upper()
        if method == "PUT":
            path = request_data.get("path", request_data.get("url", ""))
            headers = event.get("headers", {}) or {}
            status = event.get("status")
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="PUT method enabled",
                description=f"PUT method is enabled at {path}. PUT can allow file uploads and should be restricted to authenticated users.",
                evidence=f"Path: {path}\nStatus: {status}",
                remediation="Restrict PUT method to authenticated and authorized users. Validate file paths to prevent path traversal.",
                cwe="CWE-749",
            ))
        return results
