import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizUnlimitedUploadCheck(BaseCheck):
    name = "biz_unlimited_upload"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        ct = headers_lower.get("content-type", "")
        cl = headers_lower.get("content-length", "")
        if "multipart/form-data" in ct or "application/octet-stream" in ct:
            if cl and cl.isdigit():
                size_mb = int(cl) / (1024 * 1024)
                if size_mb > 100:
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="Unlimited file uploads",
                        description=f"Request has Content-Length: {cl} ({size_mb:.1f} MB). Large uploads without size limits can lead to storage exhaustion.",
                        evidence=f"Content-Length: {cl}\nContent-Type: {ct}",
                        remediation="Enforce maximum file upload size limits. Implement storage quotas per user. Validate file size before processing.",
                        cwe="CWE-770",
                    ))
        return results
