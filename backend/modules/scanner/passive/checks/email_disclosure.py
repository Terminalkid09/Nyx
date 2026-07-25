import re
from modules.scanner.base_check import BaseCheck, CheckResult


class EmailDisclosureCheck(BaseCheck):
    name = "email_disclosure"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        status = event.get("status")

        if not body and not headers_str:
            return results

        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        content_type = (headers.get("content-type") or headers.get("Content-Type") or "").lower()

        non_user_facing_contexts = [
            ct for ct in ["application/json", "application/xml", "application/x-www-form-urlencoded",
                          "multipart/form-data", "text/plain"]
            if ct in content_type
        ]

        body_emails = set()
        for match in re.finditer(email_pattern, body):
            email = match.group(0)
            domain = email.split("@")[1].lower()

            if domain in ("example.com", "example.org", "example.net", "domain.com"):
                continue

            if status and 400 <= status < 600:
                body_emails.add(email)
            elif non_user_facing_contexts:
                body_emails.add(email)

        header_emails = set()
        excluded_headers = {"from", "to", "cc", "bcc", "reply-to", "sender", "message-id",
                            "received", "return-path", "dkim-signature", "list-unsubscribe"}
        for line in headers_str.split("\n"):
            hdr_name = line.split(":")[0].strip().lower() if ":" in line else ""
            if hdr_name in excluded_headers:
                continue
            if hdr_name and hdr_name.startswith("x-"):
                continue
            for match in re.finditer(email_pattern, line):
                email = match.group(0)
                if "example" not in email.lower():
                    header_emails.add(email)

        for email in body_emails:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Email address disclosed in response body",
                description=f"Email address found in API response, error page, or raw content: {email}",
                evidence=f"Email: {email}\nContent-Type: {content_type}",
                remediation="Remove email addresses from API responses and error pages. Use generic identifiers instead.",
                cwe="CWE-200",
            ))

        for email in header_emails:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="Email address disclosed in response header",
                description=f"Email address found in response header: {email}",
                evidence=f"Email: {email}",
                remediation="Remove email addresses from response headers and use generic identifiers.",
                cwe="CWE-200",
            ))

        return results
