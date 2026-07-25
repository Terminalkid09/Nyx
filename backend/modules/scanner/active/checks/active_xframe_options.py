import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveXframeOptionsCheck(BaseCheck):
    name = "active_xframe_options"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            auth_paths = ['/login', '/auth', '/signin', '/register', '/account']
            for path in auth_paths:
                try:
                    resp = await client.get(f"{base_url}{path}", headers=req.get("headers", {}))
                    xfo = resp.headers.get("x-frame-options", "")
                    if not xfo:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title=f"Missing X-Frame-Options on {path}",
                            description=f"Authentication page at {path} is missing X-Frame-Options header, making it vulnerable to clickjacking.",
                            evidence=f"Path: {path}\nX-Frame-Options: {xfo}",
                            remediation="Add X-Frame-Options: DENY or SAMEORIGIN header to all authentication pages and sensitive endpoints.",
                            cwe="CWE-1021",
                        ))
                except Exception:
                    continue
        return results
