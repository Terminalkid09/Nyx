import re
from modules.scanner.base_check import BaseCheck, CheckResult


class FileUploadMisconfigCheck(BaseCheck):
    name = "file_upload_misconfig"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        content_type = headers_lower.get("content-type", "")
        status = event.get("status")

        upload_endpoints = re.compile(
            r"(upload|file|image|attach|media|document|asset|import|dropzone|avatar|photo|resume)",
            re.IGNORECASE
        )
        path = request_data.get("path", request_data.get("url", ""))
        is_upload_endpoint = bool(upload_endpoints.search(path))

        if not is_upload_endpoint and status != 413:
            return results

        is_binary = any(
            t in content_type for t in ["image/", "application/octet-stream", "audio/", "video/",
                                        "application/pdf", "application/zip", "multipart/"]
        ) if content_type else False

        if is_binary or is_upload_endpoint:
            xcto = headers_lower.get("x-content-type-options", "")
            if "nosniff" not in xcto:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Missing X-Content-Type-Options: nosniff on file upload endpoint",
                    description="File upload endpoint response lacks X-Content-Type-Options: nosniff, allowing MIME sniffing.",
                    evidence=f"X-Content-Type-Options: {xcto or 'not set'}\nPath: {path}",
                    remediation="Add X-Content-Type-Options: nosniff header to file serving responses.",
                    cwe="CWE-693",
                ))

            content_disposition = headers_lower.get("content-disposition", "")
            if "attachment" not in content_disposition and is_binary:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="Missing Content-Disposition: attachment for file download",
                    description="Binary file response lacks Content-Disposition: attachment, file may render inline in browser.",
                    evidence=f"Content-Disposition: {content_disposition or 'not set'}\nPath: {path}",
                    remediation="Add Content-Disposition: attachment; filename=\"...\" header to force file download.",
                    cwe="CWE-693",
                ))

        return results
