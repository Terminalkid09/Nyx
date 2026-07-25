import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/console', '/debug', '/__debugger__']
ERROR_PATTERNS = [
    (r'Werkzeug|Flask|debugger', 'Flask debug mode detected'),
    (r'Werkzeug seems to be|Interactive debugger', 'Werkzeug debugger console'),
]


class ActiveFlaskDebugCheck(BaseCheck):
    name = "active_flask_debug"

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
                                title="Flask Debug Mode / Werkzeug Console",
                                description=f"{desc}. Flask application may be running in debug mode with the Werkzeug debugger console exposed, allowing code execution.",
                                evidence=f"Path: {path}\nPattern: {pattern}",
                                remediation="Set debug=False in production. Do not use the Werkzeug development server in production.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
