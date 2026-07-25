import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliJsonResponseCheck(BaseCheck):
    name = "sqli_json_response"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r'"error".*"SQL syntax', 'SQL error in JSON error field'),
            (r'"message".*"Unclosed quotation mark', 'Unclosed quote in JSON message'),
            (r'"exception".*ORA-\d{5}', 'Oracle error in JSON exception'),
            (r'"error".*"syntax error at or near', 'PostgreSQL error in JSON error'),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SQL Injection Error in JSON Response",
                    description="SQL error messages found in JSON API responses. Error-based SQL injection may be possible through JSON endpoints.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Return generic error messages in JSON APIs. Disable database error reporting.",
                    cwe="CWE-89",
                ))
                break

        return results
