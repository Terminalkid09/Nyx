from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveHstsPreloadCheck(BaseCheck):
    name = "active_hsts_preload"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        hsts = base_request.get("headers", {}).get("Strict-Transport-Security", base_request.get("headers", {}).get("strict-transport-security", ""))
        if hsts and "preload" not in hsts.lower():
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="HSTS Preload Not Configured",
                description="HSTS header does not include the preload directive, meaning the site cannot be included in browser HSTS preload lists.",
                evidence=f"HSTS: {hsts}",
                remediation="Add preload directive to Strict-Transport-Security header and submit the domain to the HSTS preload list.",
                cwe="CWE-319",
            ))
        elif not hsts:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="HSTS Not Configured",
                description="Strict-Transport-Security header is missing, allowing SSL stripping attacks.",
                evidence="No HSTS header found",
                remediation="Implement HSTS with a reasonable max-age (e.g., 31536000) and include preload directive.",
                cwe="CWE-319",
            ))
        return results
