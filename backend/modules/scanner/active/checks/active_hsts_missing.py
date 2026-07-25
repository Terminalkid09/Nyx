import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveHstsMissingCheck(BaseCheck):
    name = "active_hsts_missing"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10, follow_redirects=True) as client:
            try:
                resp = await client.get(base_request.get("url", ""))
                hsts = resp.headers.get("strict-transport-security", "")
                if not hsts:
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="HSTS Header Missing",
                        description="Response does not include Strict-Transport-Security header.",
                        evidence=f"URL: {base_request.get('url', '')}",
                        remediation="Add Strict-Transport-Security header with min-age >= 31536000 and includeSubDomains.",
                        cwe="CWE-319",
                    ))
                elif "max-age=0" in hsts.lower():
                    results.append(CheckResult(
                        triggered=True,
                        severity="low",
                        title="HSTS Header Set to Zero",
                        description="HSTS max-age=0 effectively disables HSTS.",
                        evidence=f"Header: {hsts}",
                        remediation="Remove max-age=0 or set a positive value.",
                        cwe="CWE-319",
                    ))
            except Exception:
                pass
        return results
