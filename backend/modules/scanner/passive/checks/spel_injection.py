import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SpelInjectionCheck(BaseCheck):
    name = "spel_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        spel_patterns = [
            (r"T\(java\.lang\.Runtime\)", "SpEL: T(java.lang.Runtime)"),
            (r"T\(java\.lang\.System\)", "SpEL: T(java.lang.System)"),
            (r"T\(java\.lang\.ProcessBuilder\)", "SpEL: T(java.lang.ProcessBuilder)"),
            (r"new\s+java\.lang\.ProcessBuilder", "SpEL: new ProcessBuilder"),
            (r"exec\(.*?\)", "SpEL: exec() call"),
            (r"getRuntime\(\)", "SpEL: getRuntime() call"),
            (r"#\{.*?\}", "SpEL: #{...} expression"),
        ]
        for pattern, desc in spel_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Spring Expression Language (SpEL) injection detected",
                    description=f"{desc} found. SpEL injection can lead to remote code execution.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Do not evaluate user input as SpEL expressions. Use SimpleEvaluationContext instead of StandardEvaluationContext when evaluating expressions.",
                    cwe="CWE-917",
                ))
                break
        return results
