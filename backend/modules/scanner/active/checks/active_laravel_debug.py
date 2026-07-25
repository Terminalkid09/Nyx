import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/_debugbar', '/debugbar', '/whoops', '/ignition']
ERROR_PATTERNS = [
    (r'Whoops!|Laravel|Ignition|debugbar', 'Laravel debug mode detected'),
    (r'APP_DEBUG|APP_KEY|DB_HOST|DB_USERNAME', 'Laravel env exposure'),
]


class ActiveLaravelDebugCheck(BaseCheck):
    name = "active_laravel_debug"

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
                                title="Laravel Debug Mode Detected",
                                description=f"{desc}. Laravel application appears to have APP_DEBUG=true, exposing error pages and environment variables.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Set APP_DEBUG=false in .env file for production. Use custom error pages.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
