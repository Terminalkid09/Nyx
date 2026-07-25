import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeParameterEntitiesCheck(BaseCheck):
    name = "xxe_parameter_entities"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']file://", "Parameter entity: file read"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']http://", "Parameter entity: HTTP request"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']https://", "Parameter entity: HTTPS request"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']ftp://", "Parameter entity: FTP request"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']php://", "Parameter entity: PHP stream"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']expect://", "Parameter entity: expect command"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']data://", "Parameter entity: data URI"),
            (r"<!ENTITY\s+%\s+\w+\s+SYSTEM\s+[\"']gopher://", "Parameter entity: gopher protocol"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XXE via parameter entities",
                    description=f"{desc}. Parameter entities in XML DTD can be used to read files or make HTTP requests.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable DTD processing entirely in your XML parser. Parameter entities are processed during DTD parsing.",
                    cwe="CWE-611",
                ))
                break
        return results
