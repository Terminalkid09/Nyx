import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveDefaultAdmin3Check(BaseCheck):
    name = "active_default_admin3"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            admin_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/admin/login']
            for path in admin_paths:
                try:
                    resp = await client.post(f"{base_url}{path}", data={"username": "root", "password": "root"}, headers=req.get("headers", {}), allow_redirects=False)
                    if resp.status_code in [200, 302, 301] and "login" not in resp.url.path.lower():
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Default Admin Credentials (root:root)",
                            description=f"Admin panel at {path} accepts default {user}:root credentials, allowing unauthorized access.",
                            evidence=f"Path: {path}\nCredentials: root:root",
                            remediation="Change all default credentials immediately. Enforce strong password policies. Disable default accounts.",
                            cwe="CWE-798",
                        ))
                except Exception:
                    continue
        return results
