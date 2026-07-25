import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliErrorMssqlCheck(BaseCheck):
    name = "sqli_error_mssql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"Microsoft OLE DB.*SQL Server", "MSSQL OLE DB provider"),
            (r"Unclosed quotation mark after", "MSSQL unclosed quotation"),
            (r"Microsoft\.Jet\.OLEDB", "MSSQL Jet OLEDB"),
            (r"SQL Server.*Driver", "MSSQL driver error"),
            (r"DRIVER.*SQL Server", "MSSQL driver connection error"),
            (r"Driver\{SQL Server\}", "MSSQL driver reference"),
            (r"\[SQL Server\]", "MSSQL server error"),
            (r"Server\s+.*\s+in\s+sys\.servers", "MSSQL sys.servers error"),
            (r"Incorrect syntax near", "MSSQL syntax error"),
            (r"Line\s+\d+:", "MSSQL line number error"),
            (r"String or binary data would be truncated", "MSSQL truncation error"),
            (r"Procedure\s+'.*'\s+expects parameter", "MSSQL procedure parameter error"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Error-based MSSQL SQL injection detected",
                    description=f"{desc}. MSSQL error messages indicate potential SQL injection vulnerability.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Disable detailed MSSQL error messages in production.",
                    cwe="CWE-89",
                ))
                break
        return results
