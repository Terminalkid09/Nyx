import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CspBypassCheck(BaseCheck):
    name = "csp_bypass"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        csp = headers_lower.get("content-security-policy", "")
        if not csp:
            return results

        csp_lower = csp.lower()

        if "script-src 'unsafe-inline'" in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="CSP bypass: script-src 'unsafe-inline'",
                description="CSP allows inline scripts via 'unsafe-inline'. This weakens XSS protection.",
                evidence=f"CSP: {csp}",
                remediation="Remove 'unsafe-inline' from script-src. Use nonces or hashes for inline scripts.",
                cwe="CWE-693",
            ))

        if "script-src 'unsafe-eval'" in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CSP bypass: script-src 'unsafe-eval'",
                description="CSP allows eval() via 'unsafe-eval'. This weakens XSS protection.",
                evidence=f"CSP: {csp}",
                remediation="Remove 'unsafe-eval' from script-src. Use nonces or hashes instead.",
                cwe="CWE-693",
            ))

        if "base-uri" not in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CSP missing base-uri directive",
                description="CSP does not include base-uri directive. This allows base tag injection attacks.",
                evidence=f"CSP: {csp}",
                remediation="Add 'base-uri' directive to CSP to restrict base tag injection.",
                cwe="CWE-693",
            ))

        if "object-src" not in csp_lower:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="CSP missing object-src directive",
                description="CSP does not include object-src directive. Plugins may be loaded.",
                evidence=f"CSP: {csp}",
                remediation="Add 'object-src' directive to CSP to restrict plugin loading.",
                cwe="CWE-693",
            ))
        return results
