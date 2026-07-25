import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliErrorPostgresqlCheck(BaseCheck):
    name = "sqli_error_postgresql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"PG::SyntaxError", "PostgreSQL syntax error"),
            (r"PG::UndefinedTable", "PostgreSQL undefined table"),
            (r"PG::UndefinedColumn", "PostgreSQL undefined column"),
            (r"pg_query\(\):.*failed", "PostgreSQL query failed"),
            (r"pg_exec\(\):.*failed", "PostgreSQL exec failed"),
            (r"unterminated quoted string", "PostgreSQL unterminated string"),
            (r"ERROR:\s\s*duplicate key", "PostgreSQL duplicate key"),
            (r"ERROR:\s\s*null value", "PostgreSQL null value error"),
            (r"ERROR:\s\s*relation\s+['\"].*['\"]\s+does not exist", "PostgreSQL relation not found"),
            (r"ERROR:\s\s*column\s+['\"].*['\"]\s+does not exist", "PostgreSQL column not found"),
            (r"ERROR:\s\s*syntax error at or near", "PostgreSQL syntax error near"),
            (r"invalid input syntax for type", "PostgreSQL invalid input syntax"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Error-based PostgreSQL SQL injection detected",
                    description=f"{desc}. PostgreSQL error messages indicate potential SQL injection vulnerability.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Disable detailed PostgreSQL error messages in production.",
                    cwe="CWE-89",
                ))
                break
        return results
