import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssNewFunctionCheck(BaseCheck):
    name = "xss_new_function"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"new\s+Function\s*\(\s*['\"][^'\"]*['\"]\s*\)", "new Function() with static string"),
            (r"new\s+Function\s*\(\s*[^'\",]+\s*\)", "new Function() with variable"),
            (r"new\s+Function\s*\(\s*['\"][^'\"]*\$\{", "new Function() with template literal"),
            (r"new\s+Function\s*\(\s*['\"].*\+[^,]*['\"]", "new Function() with concatenation"),
            (r"Function\s*\(\s*['\"].*['\"].*['\"]", "Function() constructor with code string"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via new Function() constructor",
                    description=f"{desc}. The Function constructor creates functions from strings, similar to eval(). If user input reaches it, XSS is possible.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Avoid the Function constructor with user input. Use predefined functions instead.",
                    cwe="CWE-79",
                ))
                break
        return results
