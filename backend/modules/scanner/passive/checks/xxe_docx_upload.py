import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeDocxUploadCheck(BaseCheck):
    name = "xxe_docx_upload"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()
        if not body or "wordprocessing" not in ct and "officedocument" not in ct and "multipart" not in ct:
            return results
        patterns = [
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']file://", "XXE in DOCX: file read entity"),
            (r"<!DOCTYPE\s+\w+\s+\[", "DOCTYPE in DOCX XML"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM", "Parameter entity in DOCX XML"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XXE via DOCX upload",
                    description=f"{desc}. DOCX files contain XML that may be vulnerable to XXE attacks.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable external entity processing when parsing XML inside Word documents.",
                    cwe="CWE-611",
                ))
                break
        return results
