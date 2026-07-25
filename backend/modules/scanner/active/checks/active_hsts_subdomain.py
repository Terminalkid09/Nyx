import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveHstsSubdomainCheck(BaseCheck):
    name = "active_hsts_subdomain"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        req = dict(base_request)
        parsed = urlparse(req.get("url", ""))
        hsts = req.get("headers", {}).get("Strict-Transport-Security", req.get("headers", {}).get("strict-transport-security", ""))
        if hsts and "includeSubDomains" not in hsts:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Missing HSTS includeSubDomains Directive",
                description="HSTS header does not include the includeSubDomains directive, leaving subdomains vulnerable to SSL stripping.",
                evidence=f"HSTS: {hsts}",
                remediation="Add includeSubDomains directive to the Strict-Transport-Security header. Ensure all subdomains support HTTPS.",
                cwe="CWE-319",
            ))
        return results
