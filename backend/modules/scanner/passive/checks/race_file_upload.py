import re
from modules.scanner.base_check import BaseCheck, CheckResult


class RaceFileUploadCheck(BaseCheck):
    name = "race_file_upload"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        method = request_data.get("method", event.get("method", "GET")).upper()
        upload_keywords = ["upload", "file", "image", "media", "attach", "import", "dropzone", "avatar", "photo"]
        is_upload = any(k in path.lower() for k in upload_keywords)
        if is_upload and method in ("POST", "PUT", "PATCH"):
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Race condition in file upload",
                description=f"File upload endpoint at '{path}'. Race conditions in file upload processing can lead to file corruption, overwrite, or bypass of validation.",
                evidence=f"Path: {path}\nMethod: {method}",
                remediation="Use atomic file operations with unique temporary filenames. Implement proper file locking during upload processing.",
                cwe="CWE-362",
            ))
        return results
