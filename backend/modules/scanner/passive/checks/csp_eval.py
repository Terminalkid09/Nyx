from modules.scanner.base_check import BaseCheck, CheckResult


class CspEvalCheck(BaseCheck):
    name = "csp_eval"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        csp = headers_lower.get("content-security-policy", "")
        if not csp:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Content-Security-Policy header missing",
                description="No CSP header found. XSS attacks have wider impact without a policy.",
                evidence="Content-Security-Policy header not found",
                remediation="Define a strict Content-Security-Policy header.",
                cwe="CWE-693",
            ))
            return results

        csp_lower = csp.lower()

        if "unsafe-eval" in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CSP allows 'unsafe-eval'",
                description="The CSP includes 'unsafe-eval', allowing eval(), setTimeout(string), and similar functions.",
                evidence=csp[:300],
                remediation="Remove 'unsafe-eval' from CSP. Use JSON.parse instead of eval.",
                cwe="CWE-693",
            ))

        if "unsafe-inline" in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CSP allows 'unsafe-inline'",
                description="The CSP includes 'unsafe-inline', allowing inline script/style execution.",
                evidence=csp[:300],
                remediation="Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                cwe="CWE-693",
            ))

        if "default-src" not in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="CSP missing default-src directive",
                description="No default-src directive in CSP. Fallback behavior may be too permissive for unspecified directives.",
                evidence=csp[:300],
                remediation="Add a default-src directive as a fallback for all resource types.",
                cwe="CWE-693",
            ))

        return results
