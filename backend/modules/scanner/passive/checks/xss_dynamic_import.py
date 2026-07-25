import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssDynamicImportCheck(BaseCheck):
    name = "xss_dynamic_import"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"Function\s*\(\s*['\"].*import\s*\(['\"]", "Function() with dynamic import"),
            (r"setTimeout\s*\(\s*['\"].*import\s*\(", "setTimeout with dynamic import string"),
            (r"setInterval\s*\(\s*['\"].*import\s*\(", "setInterval with dynamic import string"),
            (r"eval\s*\(\s*['\"].*import\s*\(", "eval() with dynamic import"),
            (r"new\s+Function\s*\(\s*['\"].*import\s*\(", "new Function() with dynamic import"),
            (r"\$\{.*import\s*\([^}]*\}", "template literal with dynamic import"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via dynamic import() in eval context",
                    description=f"{desc}. Dynamic import() used in a string evaluation context can be exploited.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Avoid passing user input to dynamic import(). Use a whitelist of allowed module paths.",
                    cwe="CWE-79",
                ))
                break
        return results
