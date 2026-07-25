import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliTimeIndicatorsCheck(BaseCheck):
    name = "sqli_time_indicators"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"SLEEP\(\d+\)", "MySQL time-based SQLi function SLEEP()"),
            (r"WAITFOR\s+DELAY", "MSSQL time-based WAITFOR DELAY"),
            (r"pg_sleep\(\d+\)", "PostgreSQL time-based pg_sleep()"),
            (r"DBMS_LOCK\.SLEEP\(\d+\)", "Oracle time-based DBMS_LOCK.SLEEP()"),
            (r"BENCHMARK\(\d+", "MySQL BENCHMARK function"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Potential Time-Based SQL Injection Indicators",
                    description="Response timing patterns suggest possible time-based blind SQL injection. Unusual delays may indicate SLEEP or WAITFOR commands.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Ensure no user input reaches SQL query strings. Implement query timeout limits.",
                    cwe="CWE-89",
                ))
                break

        return results
