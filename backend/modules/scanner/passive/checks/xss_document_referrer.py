import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssDocumentReferrerCheck(BaseCheck):
    name = "xss_document_referrer"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"document\.referrer[^;]*\)", "document.referrer used unsafely"),
            (r"\.innerHTML\s*=\s*document\.referrer", "document.referrer in innerHTML"),
            (r"\.outerHTML\s*=\s*document\.referrer", "document.referrer in outerHTML"),
            (r"document\.write\s*\(\s*document\.referrer", "document.write with referrer"),
            (r"eval\s*\(\s*document\.referrer", "eval with document.referrer"),
            (r"new\s+Function\s*\(\s*document\.referrer", "new Function() with referrer"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via document.referrer",
                    description=f"{desc}. The Referer header can be controlled by an attacker and may contain XSS payloads.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Sanitize document.referrer before using it in DOM operations. Validate and encode the referrer value.",
                    cwe="CWE-79",
                ))
                break
        return results
