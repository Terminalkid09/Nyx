import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssErrorStackCheck(BaseCheck):
    name = "xss_error_stack"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"Error\(\)\.stack", "Error().stack access"),
            (r"new\s+Error\(\)\.stack", "new Error().stack"),
            (r"\.stack\s*\)", ".stack property accessed"),
            (r"\.stack\s*;", ".stack property used"),
        ]
        for pattern, _ in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Error().stack information disclosure",
                    description="The page accesses Error().stack which may leak internal implementation details including URLs, function names, and file paths.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Avoid exposing stack traces to users. Strip sensitive information from error messages in production.",
                    cwe="CWE-200",
                ))
                break
        dangerous = [
            (r"\.innerHTML\s*=\s*\w+\.stack", "stack trace written to innerHTML"),
            (r"\.outerHTML\s*=\s*\w+\.stack", "stack trace written to outerHTML"),
            (r"document\.write\s*\(\s*\w+\.stack", "stack trace in document.write"),
            (r"insertAdjacentHTML.*\w+\.stack", "stack trace in insertAdjacentHTML"),
        ]
        for pattern, desc in dangerous:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via Error().stack in DOM sink",
                    description=f"{desc}. Stack traces may contain attacker-controlled data leading to XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not write stack traces directly into the DOM. Encode all output properly.",
                    cwe="CWE-79",
                ))
                break
        return results
