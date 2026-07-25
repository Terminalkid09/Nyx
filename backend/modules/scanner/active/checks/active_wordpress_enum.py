import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/wp-json/wp/v2/users', '/?author=1', '/wp-json/wp/v2/users/1', '/author/admin']
ERROR_PATTERNS = [
    (r'"id":\s*\d+,\s*"name"', 'WordPress user enumeration'),
    (r'"registered_date"', 'WordPress user API exposure'),
]


class ActiveWordpressEnumCheck(BaseCheck):
    name = "active_wordpress_enum"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for path in PATHS:
                try:
                    req = dict(base_request)
                    parsed = urlparse(req.get("url", ""))
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    resp = await client.get(f"{base_url}{path}", headers=req.get("headers", {}))
                    for pattern, desc in ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="WordPress User Enumeration",
                                description=f"{desc}. WordPress author/user enumeration is possible, allowing user list harvesting.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Disable REST API user endpoints. Use plugins to block author scanning.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
