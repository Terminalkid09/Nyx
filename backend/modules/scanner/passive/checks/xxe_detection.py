import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeDetectionCheck(BaseCheck):
    name = "xxe_detection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or ""
        if not body:
            return results

        xxe_patterns = [
            (r"<!DOCTYPE\s+\w+\s+\[", "DOCTYPE declaration with internal subset"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']", "ENTITY with SYSTEM identifier"),
            (r"<!ENTITY\s+\w+\s+PUBLIC\s+[\"']", "ENTITY with PUBLIC identifier"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM", "Parameter ENTITY with SYSTEM"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']file://", "File read via ENTITY SYSTEM"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']http://", "HTTP ENTITY SYSTEM"),
            (r"<!DOCTYPE\s+\w+\s+SYSTEM", "DOCTYPE with SYSTEM identifier"),
        ]
        for pattern, desc in xxe_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XML External Entity (XXE) detected",
                    description=f"{desc} found in request body. The application may be vulnerable to XXE attacks.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Disable XML external entity processing. Use JSON or other less complex data formats. Configure XML parser to disable DTDs and external entities.",
                    cwe="CWE-611",
                ))
                break
        return results
