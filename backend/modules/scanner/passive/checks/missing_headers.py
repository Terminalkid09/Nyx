from modules.scanner.base_check import BaseCheck, CheckResult

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "cwe": "CWE-319",
        "description": "HSTS header missing. Browser may downgrade HTTPS to HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "cwe": "CWE-693",
        "description": "CSP header missing. XSS attacks have wider impact without it.",
        "remediation": "Define a strict Content-Security-Policy policy.",
    },
    "X-Frame-Options": {
        "severity": "low",
        "cwe": "CWE-1021",
        "description": "Clickjacking protection header missing.",
        "remediation": "Add: X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cwe": "CWE-430",
        "description": "MIME sniffing protection missing.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "cwe": "CWE-200",
        "description": "Referrer-Policy header missing. Referrer information may leak in URLs.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
}


class MissingHeadersCheck(BaseCheck):
    name = "missing_security_headers"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in headers_lower:
                results.append(CheckResult(
                    triggered=True,
                    severity=meta["severity"],
                    title=f"Missing security header: {header}",
                    description=meta["description"],
                    evidence=f"Header '{header}' not found in response",
                    remediation=meta["remediation"],
                    cwe=meta["cwe"],
                ))
        return results
