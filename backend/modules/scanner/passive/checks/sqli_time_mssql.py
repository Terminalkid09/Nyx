import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliTimeMssqlCheck(BaseCheck):
    name = "sqli_time_mssql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        if not combined:
            return results
        patterns = [
            (r"WAITFOR\s+DELAY\s+['\"]?\d+:\d+:\d+", "MSSQL WAITFOR DELAY"),
            (r"WAITFOR\s+TIME\s+['\"]?\d+:\d+:\d+", "MSSQL WAITFOR TIME"),
            (r";\s*WAITFOR\s+DELAY", "MSSQL WAITFOR DELAY (stacked)"),
            (r"';WAITFOR\s+DELAY", "MSSQL WAITFOR DELAY (injection)"),
            (r"AND\s+\d+\s*=\s*\d+\s*WAITFOR\s+DELAY", "MSSQL AND-WAITFOR"),
            (r"OR\s+\d+\s*=\s*\d+\s*WAITFOR\s+DELAY", "MSSQL OR-WAITFOR"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Time-based MSSQL SQL injection detected",
                    description=f"{desc}. Time-based MSSQL injection payloads found. WAITFOR DELAY introduces timing delays for blind extraction.",
                    evidence=f"Pattern: {pattern}\nURL: {url}\nBody: {body[:300]}",
                    remediation="Use parameterised queries. WAITFOR DELAY is a common time-based blind SQLi technique for MSSQL.",
                    cwe="CWE-89",
                ))
                break
        return results
