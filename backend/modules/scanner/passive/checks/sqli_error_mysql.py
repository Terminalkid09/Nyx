import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliErrorMysqlCheck(BaseCheck):
    name = "sqli_error_mysql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"SQL syntax.*MySQL", "MySQL syntax error"),
            (r"mysql_fetch_array\(\)", "MySQL fetch array error"),
            (r"mysql_num_rows\(\)", "MySQL num rows error"),
            (r"mysql_query\(\)", "MySQL query function error"),
            (r"Table\s+'.*'\s+doesn't\s+exist", "MySQL table doesn't exist"),
            (r"Unknown\s+column\s+'.*'\s+in\s+'.*'", "MySQL unknown column"),
            (r"You\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax", "MySQL syntax error"),
            (r"Duplicate\s+entry\s+'.*'\s+for\s+key", "MySQL duplicate entry"),
            (r"Warning:\s+mysql_", "MySQL warning"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Error-based MySQL SQL injection detected",
                    description=f"{desc}. MySQL error messages in responses indicate potential SQL injection vulnerability.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries / prepared statements. Disable MySQL error reporting in production.",
                    cwe="CWE-89",
                ))
                break
        return results
