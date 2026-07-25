import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliTimePostgresqlCheck(BaseCheck):
    name = "sqli_time_postgresql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        if not combined:
            return results
        patterns = [
            (r"pg_sleep\s*\(\s*\d+", "PostgreSQL pg_sleep()"),
            (r"PG_SLEEP\s*\(\s*\d+", "PostgreSQL PG_SLEEP()"),
            (r"AND\s+pg_sleep\s*\(\s*\d+", "PostgreSQL AND pg_sleep"),
            (r"OR\s+pg_sleep\s*\(\s*\d+", "PostgreSQL OR pg_sleep"),
            (r"';SELECT\s+pg_sleep", "PostgreSQL pg_sleep injection"),
            (r"';select\s+pg_sleep", "PostgreSQL pg_sleep injection (lowercase)"),
            (r"\\\\;select\s+pg_sleep", "PostgreSQL stacked pg_sleep"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Time-based PostgreSQL SQL injection detected",
                    description=f"{desc}. pg_sleep() is used for time-based blind SQL injection in PostgreSQL.",
                    evidence=f"Pattern: {pattern}\nURL: {url}\nBody: {body[:300]}",
                    remediation="Use parameterised queries. pg_sleep() creates time delays for blind data extraction.",
                    cwe="CWE-89",
                ))
                break
        return results
