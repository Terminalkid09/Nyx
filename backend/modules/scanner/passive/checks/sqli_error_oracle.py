import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliErrorOracleCheck(BaseCheck):
    name = "sqli_error_oracle"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"ORA-\d{5}", "Oracle ORA error code"),
            (r"ORA-\d{4}", "Oracle ORA short error"),
            (r"Oracle.*Driver", "Oracle driver error"),
            (r"Oracle.*OCI", "Oracle OCI error"),
            (r"PLS-\d{5}", "Oracle PLS error"),
            (r"SP2-\d{4}", "Oracle SP2 error"),
            (r"LPX-\d{4}", "Oracle LPX error"),
            (r"java\.sql\.SQLException.*Oracle", "Oracle JDBC error"),
            (r"oracle\.jdbc", "Oracle JDBC driver reference"),
            (r"invalid\s+username/password", "Oracle invalid credentials"),
            (r"table or view does not exist", "Oracle table/view not found"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Error-based Oracle SQL injection detected",
                    description=f"{desc}. Oracle error messages indicate potential SQL injection vulnerability.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Disable detailed Oracle error messages in production.",
                    cwe="CWE-89",
                ))
                break
        return results
