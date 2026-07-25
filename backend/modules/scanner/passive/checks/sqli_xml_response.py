import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SqliXmlResponseCheck(BaseCheck):
    name = "sqli_xml_response"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"<faultstring>.*ORA-\d{5}", "Oracle error in SOAP fault"),
            (r"<faultstring>.*SQL syntax", "SQL syntax error in SOAP fault"),
            (r"<soap:Fault>.*<faultstring>.*Unclosed", "SQL injection via SOAP"),
            (r"<error>.*SQL.*</error>", "SQL error in XML error element"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SQL Injection Error in XML/SOAP Response",
                    description="SQL error messages found in XML or SOAP responses. These endpoints may be vulnerable to error-based SQL injection.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use parameterised queries. Return generic SOAP/XML fault messages. Disable database error reporting in production.",
                    cwe="CWE-89",
                ))
                break

        return results
