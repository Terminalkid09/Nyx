import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiTwigCheck(BaseCheck):
    name = "ssti_twig"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\{\{7\*7\}\}", "Twig: {{7*7}} template expression"),
            (r"\$\{7\*7\}", "Twig: ${7*7} expression"),
            (r"\{\{_self\}\}", "Twig: {{_self}} object exposed"),
            (r"\{\{app\.request\}", "Twig: app.request exposed"),
            (r"\{\{csrf_token\}\}", "Twig: csrf_token function called"),
            (r"\{\{'ajax'\}\}", "Twig: 'ajax' constant"),
            (r"\{\{dump\(\)\}\}", "Twig: dump() function called"),
            (r"\{\{include\(", "Twig: include() function called"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Twig Server-Side Template Injection",
                    description=f"{desc}. Twig template expressions evaluated server-side, indicating SSTI.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not pass user input directly to Twig template rendering. Use the 'sandbox' mode for Twig.",
                    cwe="CWE-1336",
                ))
                break
        return results
