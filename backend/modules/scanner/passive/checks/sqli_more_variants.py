import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliMoreVariantsCheck(BaseCheck):
    name = "sqli_more_variants"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        sqli_patterns = [
            (r"you have an error in your sql syntax", "MySQL error-based SQLi"),
            (r"warning: mysql", "MySQL warning"),
            (r"ORA-\d{5}", "Oracle error-based SQLi"),
            (r"ORA-\d{4}", "Oracle error code"),
            (r"pg_query\(\):.*failed", "PostgreSQL error-based SQLi"),
            (r"Microsoft OLE DB.*SQL Server", "MSSQL error-based SQLi"),
            (r"Unclosed quotation mark", "MSSQL unclosed quote"),
            (r"SQLite3::", "SQLite error-based SQLi"),
            (r"SQLite\.Exception", "SQLite exception"),
            (r"SQL syntax.*MySQL", "MySQL syntax error"),
            (r"Division by zero.*SQL", "SQL division by zero"),
            (r"Unknown column.*in field list", "MySQL unknown column"),
            (r"Table.*doesn't exist", "MySQL table not found"),
            (r"unterminated quoted string", "PostgreSQL unterminated string"),
            (r"PG::SyntaxError", "PostgreSQL syntax error"),
        ]
        for pattern, desc in sqli_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SQL injection variant detected",
                    description=f"{desc} found. SQL injection may be possible.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Use parameterised queries / prepared statements. Validate and sanitize all user input.",
                    cwe="CWE-89",
                ))
                break
        return results
