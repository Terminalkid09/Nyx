import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliHttpHeaderCheck(BaseCheck):
    name = "sqli_http_header"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"X-Powered-By:.*ORA-\d{5}", "Oracle error in X-Powered-By header"),
            (r"X-Powered-By:.*SQL syntax", "SQL syntax error in X-Powered-By"),
            (r"Server:.*ORA-\d{5}", "Oracle error in Server header"),
            (r"X-Error:.*Unclosed quotation", "Unclosed quote in custom error header"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SQL Injection Error Reflected in HTTP Headers",
                    description="SQL error messages found in HTTP response headers. Database errors leaking through headers indicate potential SQL injection.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Ensure database errors are caught and not exposed in any response headers.",
                    cwe="CWE-89",
                ))
                break

        return results
