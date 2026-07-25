import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveHttpMethodsCheck(BaseCheck):
    name = "active_http_methods"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        url = base_request.get("url", "")
        dangerous_methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            allowed = []
            for method in ["GET", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]:
                try:
                    resp = await client.request(method, url)
                    if resp.status_code not in (405, 501, 400):
                        allowed.append(method)
                except Exception:
                    continue

            for method in dangerous_methods:
                if method in allowed:
                    severity = "critical" if method == "TRACE" else "high"
                    results.append(CheckResult(
                        triggered=True,
                        severity=severity,
                        title=f"Dangerous HTTP Method Enabled: {method}",
                        description=f"The endpoint allows {method} requests.",
                        evidence=f"URL: {url}\nMethod: {method}",
                        remediation=f"Disable {method} on production endpoints. Use authentication and authorization for write methods.",
                        cwe="CWE-749",
                    ))
            if len(allowed) <= 2:
                pass
        return results
