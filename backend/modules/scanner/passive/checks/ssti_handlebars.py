import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiHandlebarsCheck(BaseCheck):
    name = "ssti_handlebars"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\{\{7\*7\}\}", "Handlebars: {{7*7}} expression"),
            (r"\{\{\{7\*7\}\}\}", "Handlebars: {{{7*7}}} triple-stash"),
            (r"\{\{#with\s+\(lookup\s+", "Handlebars: #with (lookup) helper"),
            (r"\{\{#each\s+\w+\s*\}\}", "Handlebars: #each block helper"),
            (r"\{\{#if\s+\(lookup\s+", "Handlebars: #if with lookup"),
            (r"\{\{>\s*\w+\s*\}\}", "Handlebars: {{>partial}} include"),
            (r"lookup\s+this\.constructor", "Handlebars: this.constructor access via lookup"),
            (r"lookup\s+this\.__proto__", "Handlebars: prototype access via lookup"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Handlebars Server-Side Template Injection",
                    description=f"{desc}. Handlebars expressions are being evaluated server-side, indicating SSTI vulnerability.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not pass user input to Handlebars.compile(). Use the strict mode and restrict helper access.",
                    cwe="CWE-1336",
                ))
                break
        return results
