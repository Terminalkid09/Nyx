import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeSoapCheck(BaseCheck):
    name = "xxe_soap"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"<[^:]*:[Ee]nvelope[^>]*xmlns[^>]*>", "SOAP envelope detected"),
            (r"<!DOCTYPE\s+\w+\s+\[", "DOCTYPE in SOAP XML"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']file://", "XXE in SOAP: file read"),
            (r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']http://", "XXE in SOAP: HTTP request"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM", "Parameter entity in SOAP XML"),
            (r"<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"']http", "SOAP DOCTYPE with external DTD"),
            (r"<soap:Body[^>]*><![CDATA[.*<!ENTITY", "SOAP body with entity definition"),
            (r"<!DOCTYPE\s+soap\s+\[", "DOCTYPE soap with internal entity"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XXE via SOAP XML",
                    description=f"{desc}. SOAP XML messages with entity declarations are vulnerable to XXE attacks.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable external entity processing in SOAP XML parsers. Validate SOAP messages with a strict schema.",
                    cwe="CWE-611",
                ))
                break
        return results
