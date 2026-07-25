import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SopDocumentDomainCheck(BaseCheck):
    name = "sop_document_domain"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"document\.domain\s*=\s*['\"][^'\"]*['\"]", "document.domain assignment"),
            (r"document\.domain\s*=", "document.domain written to"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                match = re.search(pattern, body)
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SOP bypass via document.domain",
                    description=f"{desc}. Setting document.domain weakens the same-origin policy by allowing cross-origin access to subdomains.",
                    evidence=f"Pattern: {pattern}\nMatch: {match.group(0) if match else ''}\nBody snippet: {body[:300]}",
                    remediation="Avoid using document.domain. Use postMessage for secure cross-origin communication.",
                    cwe="CWE-668",
                ))
                break
        return results
