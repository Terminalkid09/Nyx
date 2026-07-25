import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssWindowNameCheck(BaseCheck):
    name = "xss_window_name"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"window\.name\s*=", "window.name assignment"),
            (r"document\.write\s*\(\s*window\.name", "window.name written to document"),
            (r"\.innerHTML\s*=\s*window\.name", "window.name assigned to innerHTML"),
            (r"\.outerHTML\s*=\s*window\.name", "window.name assigned to outerHTML"),
            (r"eval\s*\(\s*window\.name", "eval() called with window.name"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via window.name",
                    description=f"{desc}. window.name persists across navigation and can be controlled by an attacker, leading to XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Sanitize window.name before using it in DOM operations. Consider clearing window.name on page load.",
                    cwe="CWE-79",
                ))
                break
        return results
