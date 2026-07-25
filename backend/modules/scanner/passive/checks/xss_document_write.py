import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssDocumentWriteCheck(BaseCheck):
    name = "xss_document_write"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"document\.write\s*\(\s*['\"][^'\"]*<script", "document.write with script tag"),
            (r"document\.write\s*\(\s*['\"][^'\"]*<img", "document.write with img tag"),
            (r"document\.write\s*\(\s*['\"][^'\"]*<svg", "document.write with svg tag"),
            (r"document\.write\s*\(\s*['\"][^'\"]*<iframe", "document.write with iframe"),
            (r"document\.write\s*\(\s*['\"][^'\"]*<input", "document.write with input"),
            (r"document\.writeln\s*\(\s*['\"][^'\"]*<", "document.writeln with HTML tags"),
            (r"document\.write\s*\(\s*[^'\"\s]+\)", "document.write with variable"),
            (r"document\.write\s*\(\s*.*\.response", "document.write from HTTP response"),
            (r"document\.write\s*\(\s*.*\.value", "document.write from form value"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via document.write in script context",
                    description=f"{desc}. document.write with unsanitized input can inject arbitrary HTML/JavaScript.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Avoid document.write() for dynamic content. Use DOM manipulation methods like textContent or createElement.",
                    cwe="CWE-79",
                ))
                break
        return results
