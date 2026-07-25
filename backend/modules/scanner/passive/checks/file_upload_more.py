import re
from modules.scanner.base_check import BaseCheck, CheckResult


class FileUploadMoreCheck(BaseCheck):
    name = "file_upload_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        content_type = headers_lower.get("content-type", "")
        if "multipart/form-data" in content_type:
            if re.search(r'filename="[^"]+\.[^"]+\.[^"]+"', body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Double extension in file upload",
                    description="Filename contains multiple extensions (e.g., file.php.jpg). This may bypass extension-based filters.",
                    evidence=f"Content-Type: {content_type}\nBody snippet: {body[:500]}",
                    remediation="Validate file extensions strictly. Reject files with multiple extensions. Use content-type validation.",
                    cwe="CWE-434",
                ))

            if re.search(r'filename="[^"]*%00[^"]*"', body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Null byte in filename detected",
                    description="Null byte (%00) found in upload filename. This may bypass extension filters.",
                    evidence=f"Body snippet: {body[:500]}",
                    remediation="Reject null bytes in filenames. Validate file extensions after null byte stripping.",
                    cwe="CWE-434",
                ))
        return results
