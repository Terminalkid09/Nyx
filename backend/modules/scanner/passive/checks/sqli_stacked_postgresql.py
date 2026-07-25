import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliStackedPostgresqlCheck(BaseCheck):
    name = "sqli_stacked_postgresql"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        if not combined:
            return results
        patterns = [
            (r";\s*SELECT\s+.*\s+FROM", "Stacked SELECT in PostgreSQL"),
            (r";\s*INSERT\s+INTO", "Stacked INSERT in PostgreSQL"),
            (r";\s*UPDATE\s+.*\s+SET", "Stacked UPDATE in PostgreSQL"),
            (r";\s*DELETE\s+FROM", "Stacked DELETE in PostgreSQL"),
            (r";\s*DROP\s+TABLE", "Stacked DROP TABLE in PostgreSQL"),
            (r";\s*CREATE\s+TABLE", "Stacked CREATE TABLE in PostgreSQL"),
            (r";\s*COPY\s+.*\s+FROM", "Stacked COPY FROM in PostgreSQL"),
            (r";\s*pg_sleep", "Stacked pg_sleep in PostgreSQL"),
            (r";\s*NOTIFY\s+", "Stacked NOTIFY in PostgreSQL"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Stacked query SQL injection in PostgreSQL",
                    description=f"{desc}. Stacked queries allow executing multiple statements, increasing SQL injection impact.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Use parameterised queries. PostgreSQL supports multiple statements per query by default.",
                    cwe="CWE-89",
                ))
                break
        return results
