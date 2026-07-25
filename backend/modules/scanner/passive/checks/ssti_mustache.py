import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiMustacheCheck(BaseCheck):
    name = "ssti_mustache"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\{\{7\*7\}\}", "Mustache: {{7*7}} expression"),
            (r"\{\{\{7\*7\}\}\}", "Mustache: {{{7*7}}} unescaped expression"),
            (r"\{\{&\s*7\*7\s*\}}", "Mustache: {{&7*7}} unescaped expression"),
            (r"\{\{#\w+\}\}", "Mustache: {{#section}} block"),
            (r"\{\{>\s*\w+\s*\}\}", "Mustache: {{>partial}} include"),
            (r"\{\{=\s*.*\s*=\}\}", "Mustache: custom delimiter change"),
            (r"\{\{!\s*.*\}\}", "Mustache: {{!comment}} detected"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Mustache/Handlebars Server-Side Template Injection",
                    description=f"{desc}. Mustache expressions evaluated server-side, indicating SSTI.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input as Mustache templates. Mustache is intentionally logic-less but partials can be abused.",
                    cwe="CWE-1336",
                ))
                break
        return results
