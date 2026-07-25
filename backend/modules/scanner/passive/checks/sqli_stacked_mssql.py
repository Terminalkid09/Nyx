import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliStackedMssqlCheck(BaseCheck):
    name = "sqli_stacked_mssql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        if not combined:
            return results
        patterns = [
            (r";\s*SELECT\s+.*\s+FROM", "Stacked SELECT in MSSQL"),
            (r";\s*INSERT\s+INTO", "Stacked INSERT in MSSQL"),
            (r";\s*UPDATE\s+.*SET", "Stacked UPDATE in MSSQL"),
            (r";\s*DELETE\s+FROM", "Stacked DELETE in MSSQL"),
            (r";\s*DROP\s+TABLE", "Stacked DROP TABLE in MSSQL"),
            (r";\s*CREATE\s+TABLE", "Stacked CREATE TABLE in MSSQL"),
            (r";\s*EXEC\s+\w+", "Stacked EXEC statement in MSSQL"),
            (r";\s*EXECUTE\s+\w+", "Stacked EXECUTE in MSSQL"),
            (r";\s*xp_cmdshell", "Stacked xp_cmdshell in MSSQL"),
            (r";\s*sp_", "Stacked stored procedure in MSSQL"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Stacked query SQL injection in MSSQL",
                    description=f"{desc}. Stacked queries allow executing multiple statements, increasing the impact of SQL injection.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Use parameterised queries. Ensure the database connection does not allow multiple statements.",
                    cwe="CWE-89",
                ))
                break
        return results
