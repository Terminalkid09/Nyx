import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssOuterhtmlCheck(BaseCheck):
    name = "xss_outerhtml"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\.outerHTML\s*=\s*['\"][^'\"]*<", "outerHTML assignment with HTML tags"),
            (r"\.outerHTML\s*=\s*.*getElementById", "outerHTML from DOM element"),
            (r"\.outerHTML\s*=\s*.*querySelector", "outerHTML from querySelector"),
            (r"\.outerHTML\s*=\s*.*response", "outerHTML from response data"),
            (r"\.outerHTML\s*=\s*.*\.value", "outerHTML from input value"),
            (r"\.outerHTML\s*=\s*.*params\[", "outerHTML from URL params"),
            (r"\.outerHTML\s*=\s*.*location\.", "outerHTML from location properties"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via .outerHTML assignments",
                    description=f"{desc}. Assigning user-controlled content to outerHTML replaces the entire element and can lead to XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Avoid outerHTML assignments with user-controlled data. Use DOM manipulation methods instead.",
                    cwe="CWE-79",
                ))
                break
        return results
