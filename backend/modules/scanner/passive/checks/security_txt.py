import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SecurityTxtCheck(BaseCheck):
    name = "security_txt"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", "")).lower()
        body = event.get("body", "") or ""
        status = event.get("status")
        content_type = (event.get("headers", {}) or {}).get("content-type", "")

        is_security_txt = path.endswith("/security.txt") or path.endswith("/.well-known/security.txt")

        if not is_security_txt:
            return results

        if status != 200:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="security.txt not accessible",
                description=f"Security.txt was requested but returned status {status}.",
                evidence=f"URL: {path}\nStatus: {status}",
                remediation="Create a security.txt file at /.well-known/security.txt according to RFC 9116.",
                cwe="CWE-200",
            ))
            return results

        required_fields = ["contact", "expires", "canonical"]
        missing_fields = []
        for field in required_fields:
            pattern = re.compile(rf"^{field}:", re.IGNORECASE | re.MULTILINE)
            if not pattern.search(body):
                missing_fields.append(field)

        contact_found = re.search(r"^contact:\s*(.+)$", body, re.IGNORECASE | re.MULTILINE)
        expires_found = re.search(r"^expires:\s*(.+)$", body, re.IGNORECASE | re.MULTILINE)

        if missing_fields:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="security.txt is missing required fields",
                description=f"Required fields missing from security.txt: {', '.join(missing_fields)}.",
                evidence=f"URL: {path}\nMissing: {', '.join(missing_fields)}\n\nBody:\n{body[:500]}",
                remediation="Include 'Contact', 'Expires', and 'Canonical' fields as per RFC 9116.",
                cwe="CWE-200",
            ))

        if contact_found:
            contact_val = contact_found.group(1).strip()
            if not contact_val.startswith("mailto:") and not contact_val.startswith("http"):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="security.txt Contact field has invalid format",
                    description="The Contact field should be a mailto: URI or https: URI.",
                    evidence=f"Contact: {contact_val}",
                    remediation="Use a mailto: URI (e.g., Contact: mailto:security@example.com) or https: URI for the Contact field.",
                    cwe="CWE-200",
                ))

        if expires_found:
            expires_val = expires_found.group(1).strip()
            if not re.search(r"\d{4}-\d{2}-\d{2}", expires_val):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="security.txt Expires field has invalid date format",
                    description="The Expires field should use ISO 8601 date format (YYYY-MM-DD).",
                    evidence=f"Expires: {expires_val}",
                    remediation="Use ISO 8601 date format: Expires: 2025-12-31T00:00:00.000Z",
                    cwe="CWE-200",
                ))

        if not missing_fields and contact_found:
            results.append(CheckResult(
                triggered=True,
                severity="info",
                title="security.txt is properly configured",
                description="A security.txt file exists with required fields.",
                evidence=f"URL: {path}\nContact: {contact_found.group(1).strip()}",
                remediation="No action needed. security.txt is properly implemented.",
                cwe="CWE-200",
            ))

        return results
