import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/doesnotexist12345', '/settings', '/settings.py', '/debug']
ERROR_PATTERNS = [
    (r'Django version|URLconf|Django tried', 'Django debug mode detected'),
    (r'DEBUG = True|SECRET_KEY|DATABASES', 'Django settings exposed'),
    (r"You're seeing this error because you have DEBUG = True", 'Django DEBUG mode'),
]


class ActiveDjangoDebugCheck(BaseCheck):
    name = "active_django_debug"

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
                                severity="high",
                                title="Django DEBUG Mode Enabled",
                                description=f"{desc}. Django application appears to be running with DEBUG=True, exposing detailed error pages, settings, and sensitive configuration.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Set DEBUG=False in production. Configure proper error handling. Use custom error pages.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
