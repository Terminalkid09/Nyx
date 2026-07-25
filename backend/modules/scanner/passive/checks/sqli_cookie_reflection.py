import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliCookieReflectionCheck(BaseCheck):
    name = "sqli_cookie_reflection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"Set-Cookie:.*ORA-\d{5}", "Oracle error in Set-Cookie header"),
            (r"Set-Cookie:.*SQL syntax", "SQL syntax error in Set-Cookie"),
            (r"Set-Cookie:.*Unclosed quotation", "Unclosed quote in Set-Cookie"),
            (r"Set-Cookie:.*mysql_fetch", "MySQL fetch error in Set-Cookie"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SQL Injection Error via Cookie Reflection",
                    description="SQL error messages reflected in response cookies. Cookie-based injection may be possible and errors are leaking into set-cookie headers.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Validate and sanitize cookie inputs. Do not reflect cookie values in error messages.",
                    cwe="CWE-89",
                ))
                break

        return results
