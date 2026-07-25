import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssInnerhtmlCheck(BaseCheck):
    name = "xss_innerhtml"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\.innerHTML\s*=\s*['\"][^'\"]*<", "innerHTML assignment with HTML tags"),
            (r"\.innerHTML\s*=\s*.*getElementById", "innerHTML from DOM element"),
            (r"\.innerHTML\s*=\s*.*querySelector", "innerHTML from querySelector"),
            (r"\.innerHTML\s*=\s*.*response", "innerHTML from response data"),
            (r"\.innerHTML\s*=\s*.*localStorage", "innerHTML from localStorage"),
            (r"\.innerHTML\s*=\s*.*sessionStorage", "innerHTML from sessionStorage"),
            (r"\.innerHTML\s*=\s*.*\.value", "innerHTML from input value"),
            (r"\.innerHTML\s*=\s*.*params\[", "innerHTML from URL params"),
            (r"\.innerHTML\s*=\s*.*location\.", "innerHTML from location properties"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via .innerHTML assignments",
                    description=f"{desc}. Assigning user-controlled or dynamic content to innerHTML can lead to XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use textContent instead of innerHTML for text content. Sanitize HTML before assigning to innerHTML.",
                    cwe="CWE-79",
                ))
                break
        return results
