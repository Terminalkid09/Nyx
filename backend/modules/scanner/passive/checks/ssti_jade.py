import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiJadeCheck(BaseCheck):
    name = "ssti_jade"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"#\{7\*7\}", "Jade/Pug: #{7*7} interpolation"),
            (r"!\{7\*7\}", "Jade/Pug: !{7*7} unescaped interpolation"),
            (r"#\{[^}]*__proto__", "Jade/Pug: prototype pollution via interpolation"),
            (r"!\{[^}]*__proto__", "Jade/Pug: unescaped prototype access"),
            (r"#\{[^}]*constructor", "Jade/Pug: constructor access in interpolation"),
            (r"!\{[^}]*constructor", "Jade/Pug: unescaped constructor access"),
            (r"p=\s*[^ \n]+", "Jade/Pug: = expression inline"),
            (r"p!\s*[^ \n]+", "Jade/Pug: != unescaped expression"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Jade/Pug Server-Side Template Injection",
                    description=f"{desc}. Jade/Pug template interpolation evaluated server-side, indicating SSTI.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not pass user input to Jade/Pug template rendering functions. Use strict locals.",
                    cwe="CWE-1336",
                ))
                break
        return results
