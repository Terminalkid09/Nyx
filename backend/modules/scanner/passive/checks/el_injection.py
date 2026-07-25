import re
from modules.scanner.base_check import BaseCheck, CheckResult


class ElInjectionCheck(BaseCheck):
    name = "el_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        el_patterns = [
            (r"\$\{.*?\}", "Java Expression Language: ${...} pattern"),
            (r"#\{.*?\}", "Spring Expression Language: #{...} pattern"),
            (r"\$\{7\*7\}", "Java EL: ${7*7} evaluated"),
            (r"\$\{.*?T\(java", "Java EL: T(java.lang.Runtime) pattern"),
            (r"\$\{.*?new\s+java", "Java EL: new java.* pattern"),
            (r"\$\{.*?exec\(.*?\)\}", "Java EL: exec() call pattern"),
        ]
        for pattern, desc in el_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Expression Language (EL) injection detected",
                    description=f"{desc} found in request. EL injection may allow remote code execution.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Avoid evaluating user input as EL expressions. Use secure templating libraries. Sanitize and validate all user input.",
                    cwe="CWE-917",
                ))
                break
        return results
