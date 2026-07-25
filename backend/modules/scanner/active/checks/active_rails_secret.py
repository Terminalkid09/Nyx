import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/secrets', '/config/secrets', '/environment', '/rails/info/properties']
ERROR_PATTERNS = [
    (r'secret_key_base|Rails\.application|SECRET', 'Rails secret exposure'),
]


class ActiveRailsSecretCheck(BaseCheck):
    name = "active_rails_secret"

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
                                title="Rails Secret Key Base Exposure",
                                description=f"{desc}. Ruby on Rails application may expose secret_key_base or other sensitive credentials.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Ensure secret_key_base is stored in environment variables, not in source code. Rotate exposed keys immediately.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
