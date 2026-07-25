import re
from modules.scanner.base_check import BaseCheck, CheckResult


class HstsCheck(BaseCheck):
    name = "hsts_check"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        hsts = headers_lower.get("strict-transport-security", "")
        if not hsts:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Strict-Transport-Security header missing",
                description="HSTS header not present. Browser may allow HTTP connections to this site.",
                evidence="Strict-Transport-Security header not found",
                remediation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                cwe="CWE-319",
            ))
            return results

        hsts_lower = hsts.lower()
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 10886400:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="HSTS max-age is too short",
                    description=f"HSTS max-age is {max_age}s ({(max_age / 86400):.1f} days). Minimum recommended is 10886400s (126 days).",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    remediation="Set max-age to at least 10886400 (126 days) or preferably 31536000 (1 year).",
                    cwe="CWE-319",
                ))
        else:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="HSTS header missing max-age directive",
                description="HSTS header is present but does not contain a max-age directive.",
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Add max-age directive to HSTS header.",
                cwe="CWE-319",
            ))

        if "includesubdomains" not in hsts_lower and "includeSubDomains" not in hsts:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="HSTS missing includeSubDomains directive",
                description="HSTS does not apply to subdomains, leaving them vulnerable to SSL stripping.",
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Add 'includeSubDomains' to HSTS header to protect all subdomains.",
                cwe="CWE-319",
            ))

        if "preload" not in hsts_lower:
            results.append(CheckResult(
                triggered=True,
                severity="info",
                title="HSTS missing preload directive",
                description="HSTS does not include the 'preload' directive, so browsers cannot preload it.",
                evidence=f"Strict-Transport-Security: {hsts}",
                remediation="Add 'preload' to HSTS and submit to https://hstspreload.org/.",
                cwe="CWE-319",
            ))

        return results
