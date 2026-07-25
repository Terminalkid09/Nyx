import re
from modules.scanner.base_check import BaseCheck, CheckResult


class ElmaInjectionCheck(BaseCheck):
    name = "elma_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        elma_patterns = [
            (r"ELMA_INJECTION", "ELMA injection marker"),
            (r"elma\.", "ELMA framework reference"),
            (r"ELMA\.", "ELMA framework reference (uppercase)"),
            (r"elma_injection", "ELMA injection test string"),
            (r"\{\{elma", "ELMA template pattern"),
        ]
        for pattern, desc in elma_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="ELMA injection detected",
                    description=f"{desc} found. ELMA template injection may allow server-side code execution.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Sanitize user input before passing to ELMA template engine. Use sandboxed template rendering.",
                    cwe="CWE-917",
                ))
                break
        return results
