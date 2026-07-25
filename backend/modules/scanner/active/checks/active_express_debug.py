import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/error', '/throw', '/cause_error']
ERROR_PATTERNS = [
    (r'at\s+\w+\.\w+\s+\(', 'Node.js stack trace'),
    (r'Error:\s+.*\n\s+at\s+', 'Express.js error with stack'),
    (r'node_modules|app\.js|index\.js|route', 'Express.js path disclosure'),
]


class ActiveExpressDebugCheck(BaseCheck):
    name = "active_express_debug"

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
                                title="Express.js Stack Traces Enabled",
                                description=f"{desc}. Express.js application appears to expose stack traces in error responses.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Set NODE_ENV=production to disable stack traces. Implement custom error handling middleware.",
                                cwe="CWE-209",
                            ))
                            break
                except Exception:
                    continue
        return results
