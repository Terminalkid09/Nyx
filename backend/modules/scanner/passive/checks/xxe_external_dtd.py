import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeExternalDtdCheck(BaseCheck):
    name = "xxe_external_dtd"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"']http", "DOCTYPE with external HTTP DTD"),
            (r"<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"']https", "DOCTYPE with external HTTPS DTD"),
            (r"<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"']file://", "DOCTYPE with external file DTD"),
            (r"<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"']ftp://", "DOCTYPE with external FTP DTD"),
            (r"<!DOCTYPE\s+\w+\s+PUBLIC\s+[\"'][^\"']+[\"']\s+[\"']http", "DOCTYPE PUBLIC with external HTTP DTD"),
            (r"<!DOCTYPE\s+\w+\s+PUBLIC\s+[\"'][^\"']+[\"']\s+[\"']file://", "DOCTYPE PUBLIC with external file DTD"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XXE via external DTD",
                    description=f"{desc}. External DTD declarations allow loading remote DTD files, which can be used for blind XXE exfiltration.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable external DTD loading. DTDs are not needed for most XML processing scenarios.",
                    cwe="CWE-611",
                ))
                break
        return results
