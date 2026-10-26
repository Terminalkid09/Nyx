"""Error-based SQL injection detection.

Deliberately limited to *error* signatures. Blind/time-based detection lives
in ``active_sqli_blind`` and ``active_time_blind``, which calibrate a baseline
before drawing conclusions. This check used to treat any request that timed
out while carrying a SLEEP payload as a vulnerability: a slow endpoint was
enough to produce a high-severity false positive.
"""
import copy
import re
import urllib.parse

import httpx

from modules.scanner.base_check import BaseCheck, CheckResult, cap_payloads

SQLI_ERROR_PATTERNS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"pg_query\(\): Query failed", "PostgreSQL"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"Unclosed quotation mark after", "MSSQL"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"SQLSTATE\[", "PDO"),
]

# No destructive statements (DROP/DELETE/UPDATE) and no time-based payloads:
# an error signature cannot be produced by a benign slow response.
SQLI_PAYLOADS = [
    "'",
    "''",
    "1' OR '1'='1",
    "1'' OR 1=1--",
    "1' OR '1'='1' --",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL, NULL--",
    "1' ORDER BY 100--",
    "1' AND extractvalue(1,concat(0x7e,version()))--",
    "1 AND 1=CAST((SELECT version()) AS int)--",
]


class SQLiCheck(BaseCheck):
    name = "active_sqli"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload in cap_payloads(SQLI_PAYLOADS):
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                    except Exception:
                        continue
                    for pattern, db_type in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, resp.text or "", re.IGNORECASE):
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title=f"SQL Injection detected ({db_type})",
                                description=f"Parameter '{param}' is vulnerable to error-based SQL injection.",
                                evidence=(
                                    f"Payload: {payload}\nDatabase: {db_type}\n"
                                    f"Status: {resp.status_code}\n"
                                    f"Response snippet: {(resp.text or '')[:300]}"
                                ),
                                remediation="Use parameterised queries / prepared statements.",
                                cwe="CWE-89",
                                param=param,
                            ))
                            break
        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
