import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssImportCheck(BaseCheck):
    name = "xss_import"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"import\s*\(\s*['\"][^'\"]*javascript:", "import() with javascript: URI"),
            (r"import\s*\(\s*['\"][^'\"]*data:text/html", "import() with data: HTML"),
            (r"import\s*\(\s*url\s*\)", "import() with variable (potential injection)"),
            (r"import\s*\(\s*['\"][^'\"]*\$\{", "import() with template literal injection"),
            (r"import\s*\(\s*['\"][^'\"]*['\"]\s*\.\s*concat\s*\(", "import() with concat injection"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via import() injection",
                    description=f"{desc}. Dynamic import() with attacker-controlled input can lead to XSS.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Validate and sanitize any user input passed to dynamic import(). Use static imports when possible.",
                    cwe="CWE-79",
                ))
                break
        return results
