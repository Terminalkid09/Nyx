import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiFreemarkerCheck(BaseCheck):
    name = "ssti_freemarker"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\$\{7\*7\}", "Freemarker: ${7*7} expression"),
            (r"\$\{\.\.\.?\}", "Freemarker: ${...} expression pattern"),
            (r"\$\{2\*2\}", "Freemarker: ${2*2} expression"),
            (r"\#\{7\*7\}", "Freemarker: #{7*7} expression"),
            (r"\$\{class\.forName", "Freemarker: class.forName access"),
            (r"\$\{object\.getClass", "Freemarker: object.getClass access"),
            (r"\$\{session\}", "Freemarker: ${session} object"),
            (r"\$\{request\}", "Freemarker: ${request} object"),
            (r"\$\{application\}", "Freemarker: ${application} object"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Freemarker Server-Side Template Injection",
                    description=f"{desc}. Freemarker template expressions are being evaluated server-side.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input in Freemarker templates. Use the template resolver with restricted access.",
                    cwe="CWE-1336",
                ))
                break
        return results
