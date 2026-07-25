import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoStackTraceCheck(BaseCheck):
    name = "info_stack_trace"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"at\s+[\w.]+\([\w./\\]+:\d+:\d+\)", "Stack frame with file:line:col"),
            (r"at\s+[\w.]+\([\w./\\]+:\d+\)", "Stack frame with file:line"),
            (r"File\s+[\"'][\w./\\]+[\"'],\s+line\s+\d+", "File/line traceback"),
            (r"Traceback\s+\(most\s+recent\s+call\s+last\)", "Python traceback header"),
            (r"Stack trace:", "Stack trace header"),
            (r"Stack trace for", "Stack trace for context"),
            (r"at\s+[\w.]+\.\w+\([\w.]+\.java:\d+\)", "Java stack trace"),
            (r"at\s+[\w.]+\.\w+\(Unknown\s+Source\)", "Java unknown source trace"),
            (r"in\s+[\w/\\]+\.php\s+on\s+line\s+\d+", "PHP traceback"),
            (r"#\d+\s+[\w./\\]+\([\w./\\]+:\d+\)", "Ruby traceback"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Stack traces exposed",
                    description=f"{desc}. Stack traces reveal code structure, file paths, and line numbers to attackers.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Disable debug mode and detailed error pages in production. Use custom error handlers that log errors server-side.",
                    cwe="CWE-200",
                ))
                break
        return results
