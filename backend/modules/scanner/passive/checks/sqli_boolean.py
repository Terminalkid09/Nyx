import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliBooleanCheck(BaseCheck):
    name = "sqli_boolean"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("response_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        if not combined:
            return results
        patterns = [
            (r"1' AND '1'='1", "Boolean: 1' AND '1'='1"),
            (r"1' AND '1'='2", "Boolean: 1' AND '1'='2"),
            (r"1' AND 1=1--", "Boolean: 1' AND 1=1--"),
            (r"1' AND 1=2--", "Boolean: 1' AND 1=2--"),
            (r"admin' OR '1'='1", "Boolean: admin' OR '1'='1"),
            (r"admin' OR '1'='2", "Boolean: admin' OR '1'='2"),
            (r"1\s+AND\s+SUBSTRING\s*\(", "Boolean: AND SUBSTRING conditional"),
            (r"1\s+AND\s+ASCII\s*\(", "Boolean: AND ASCII conditional"),
            (r"1\s+AND\s+ORD\s*\(", "Boolean: AND ORD conditional"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Boolean-based SQL injection detected",
                    description=f"{desc}. Boolean-based conditional payloads found, used for blind SQL injection.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Use parameterised queries. Boolean-based blind SQLi infers data through true/false responses.",
                    cwe="CWE-89",
                ))
                break
        return results
