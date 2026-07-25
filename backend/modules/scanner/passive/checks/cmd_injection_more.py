import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CmdInjectionMoreCheck(BaseCheck):
    name = "cmd_injection_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = event.get("url", "") or request_data.get("url", "")
        body = event.get("request_body", "") or ""
        combined = f"{url} {body}"

        cmd_patterns = [
            (r"`[^`]+`", "Backtick command injection"),
            (r"\$\([^)]+\)", "$() command substitution"),
            (r"\|[^|]", "Pipe command injection"),
            (r"\|\|", "OR operator command injection"),
            (r"&&", "AND operator command injection"),
            (r";\s*[a-z]", "Semicolon command injection"),
            (r"\n\s*[a-z]", "Newline command injection"),
            (r"\|&\s*[a-z]", "Pipe all command injection"),
            (r"%00", "Null byte command injection"),
            (r"`[^`]+`", "Backtick command injection"),
        ]
        for pattern, desc in cmd_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Command injection variant detected",
                    description=f"{desc} found. Command injection may allow arbitrary command execution.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Avoid shell execution with user input. Use safe APIs. Validate and sanitize all input.",
                    cwe="CWE-78",
                ))
                break
        return results
