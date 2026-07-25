import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmtpInjectionCheck(BaseCheck):
    name = "smtp_injection"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        smtp_patterns = [
            (r"%0d%0a", "URL-encoded CRLF (%0d%0a)"),
            (r"%0D%0A", "URL-encoded CRLF (%0D%0A)"),
            (r"\\r\\n", "Escaped CRLF (\\r\\n)"),
            (r"\r\n", "Raw CRLF sequence"),
            (r"%0a%0d", "URL-encoded LFCR (%0a%0d)"),
            (r"\r\n\.\r\n", "SMTP data termination (\\r\\n.\\r\\n)"),
            (r"%00", "Null byte injection"),
        ]
        for pattern, desc in smtp_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="SMTP injection detected",
                    description=f"{desc} found in request. Attacker may inject SMTP commands.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Validate and sanitize all user input. Reject newline and CRLF characters in email-related fields. Use allowlists for email headers.",
                    cwe="CWE-93",
                ))
                break
        return results
