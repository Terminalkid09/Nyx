import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliBooleanIndicatorsCheck(BaseCheck):
    name = "sqli_boolean_indicators"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"1=1.*1=2|1=2.*1=1", "Boolean conditional test visible"),
            (r"' AND \d+=\d+--", "Boolean AND condition in SQL"),
            (r"' OR \d+=\d+--", "Boolean OR condition in SQL"),
            (r"true.*false.*true|false.*true.*false", "Boolean flipping pattern"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Boolean-Based Blind SQL Injection Indicators",
                    description="Response contains patterns suggesting boolean-based blind SQL injection via conditional comparisons (1=1 vs 1=2).",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Implement consistent responses regardless of query truth values.",
                    cwe="CWE-89",
                ))
                break

        return results
