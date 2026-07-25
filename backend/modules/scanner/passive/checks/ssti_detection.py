import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiDetectionCheck(BaseCheck):
    name = "ssti_detection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        if not body:
            return results

        ssti_patterns = [
            (r"\{\{7\*7\}\}", "Jinja2/ Twig: {{7*7}} evaluated"),
            (r"\$\{7\*7\}", "Java EL / Freemarker: ${7*7} evaluated"),
            (r"#\{7\*7\}", "Ruby ERB: #{7*7} evaluated"),
            (r"\$\{\{7\*7\}\}", "Velocity: ${{7*7}} evaluated"),
            (r"\{\{config\}\}", "Jinja2: {{config}} exposed"),
            (r"\{\{self\}\}", "Jinja2: {{self}} exposed"),
            (r"\{\{app\.request\}", "Jinja2: app.request exposed"),
            (r"\{\{7\*'7'\}\}", "Jinja2: {{7*'7'}} evaluated (7777777)"),
        ]
        for pattern, desc in ssti_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Server-Side Template Injection (SSTI) detected",
                    description=f"{desc} in response body. Template expressions are being evaluated server-side.",
                    evidence=f"Pattern matched: {pattern}\nResponse snippet: {body[:500]}",
                    remediation="Do not render user input as templates. Use sandboxed template engines. Validate and sanitize all user input before passing to template rendering functions.",
                    cwe="CWE-1336",
                ))
                break
        return results
