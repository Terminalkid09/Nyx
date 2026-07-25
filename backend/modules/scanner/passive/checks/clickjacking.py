from modules.scanner.base_check import BaseCheck, CheckResult


class ClickjackingCheck(BaseCheck):
    name = "clickjacking"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        xfo = headers_lower.get("x-frame-options", "")
        csp = headers_lower.get("content-security-policy", "")

        missing_xfo = not xfo
        missing_csp_frame = "frame-ancestors" not in csp

        if missing_xfo and missing_csp_frame:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Clickjacking protection missing",
                description="Response lacks both X-Frame-Options and CSP frame-ancestors, making the page vulnerable to clickjacking.",
                evidence="X-Frame-Options: not set\nContent-Security-Policy frame-ancestors: not set",
                remediation="Add X-Frame-Options: DENY or a Content-Security-Policy with frame-ancestors directive.",
                cwe="CWE-1021",
            ))
        elif missing_xfo:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="X-Frame-Options header missing",
                description="X-Frame-Options is not set, but CSP frame-ancestors may provide protection.",
                evidence="X-Frame-Options header not found in response",
                remediation="Add X-Frame-Options: DENY for additional clickjacking protection.",
                cwe="CWE-1021",
            ))

        if xfo and xfo.lower() not in ("deny", "sameorigin"):
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="Permissive X-Frame-Options value",
                description=f"X-Frame-Options is set to '{xfo}' which may allow framing.",
                evidence=f"X-Frame-Options: {xfo}",
                remediation="Use X-Frame-Options: DENY or SAMEORIGIN.",
                cwe="CWE-1021",
            ))

        return results
