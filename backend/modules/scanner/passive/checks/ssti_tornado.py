import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiTornadoCheck(BaseCheck):
    name = "ssti_tornado"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\{\{7\*7\}\}", "Tornado: {{7*7}} expression"),
            (r"\{\{escape\(", "Tornado: {{escape()}} function"),
            (r"\{\{handler\}", "Tornado: {{handler}} object"),
            (r"\{\{request\}", "Tornado: {{request}} object"),
            (r"\{%\s*autoescape\s+\w+\s*%\}", "Tornado: {% autoescape %} tag"),
            (r"\{%\s*raw\s*%\}", "Tornado: {% raw %} tag"),
            (r"\{%\s*module\s+\w+\s*%\}", "Tornado: {% module %} tag"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Tornado Server-Side Template Injection",
                    description=f"{desc}. Tornado template expressions evaluated server-side.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input in Tornado templates. Use autoescape properly and avoid passing user data to template render.",
                    cwe="CWE-1336",
                ))
                break
        return results
