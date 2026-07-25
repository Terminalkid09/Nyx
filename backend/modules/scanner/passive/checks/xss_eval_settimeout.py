import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssEvalSetTimeoutCheck(BaseCheck):
    name = "xss_eval_settimeout"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"setTimeout\s*\(\s*['\"].*['\"]\s*,\s*\d+", "setTimeout with string code"),
            (r"setInterval\s*\(\s*['\"].*['\"]\s*,\s*\d+", "setInterval with string code"),
            (r"setTimeout\s*\(\s*['\"].*\+\s*.*['\"]", "setTimeout with string concatenation (injectable)"),
            (r"setInterval\s*\(\s*['\"].*\+\s*.*['\"]", "setInterval with string concatenation (injectable)"),
            (r"setTimeout\s*\(\s*['\"].*\$\{", "setTimeout with template literal"),
            (r"setInterval\s*\(\s*['\"].*\$\{", "setInterval with template literal"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via setTimeout/setInterval with string argument",
                    description=f"{desc}. When setTimeout/setInterval receives a string, it is evaluated like eval(), allowing XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Pass function references instead of strings to setTimeout/setInterval. Avoid string concatenation in timers.",
                    cwe="CWE-79",
                ))
                break
        return results
