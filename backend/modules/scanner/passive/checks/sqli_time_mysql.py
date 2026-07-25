import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliTimeMysqlCheck(BaseCheck):
    name = "sqli_time_mysql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        if not combined:
            return results
        patterns = [
            (r"BENCHMARK\s*\(\s*\d+\s*,", "MySQL BENCHMARK() function"),
            (r"SLEEP\s*\(\s*\d+\s*\)", "MySQL SLEEP() function"),
            (r"AND\s+SLEEP\s*\(\s*\d+", "AND SLEEP() in query"),
            (r"OR\s+SLEEP\s*\(\s*\d+", "OR SLEEP() in query"),
            (r"BENCHMARK\s*\(\s*[0-9]+\s*,\s*MD5\s*\(", "BENCHMARK with MD5"),
            (r"WAIT_FOR_EXECUTED_SQL", "MySQL wait condition"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Time-based MySQL SQL injection detected",
                    description=f"{desc}. Time-based SQL injection payloads found in request or response. These attempt to exploit timing delays.",
                    evidence=f"Pattern: {pattern}\nURL: {url}\nBody: {body[:300]}",
                    remediation="Use parameterised queries. Time-based injections exploit conditional timing to extract data.",
                    cwe="CWE-89",
                ))
                break
        return results
