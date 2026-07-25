import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

ERROR_PATTERNS = [
    (r'"version":\s*3|"sources":\s*\[|"mappings":', 'Source map file detected'),
]


class ActiveNextjsSourceCheck(BaseCheck):
    name = "active_nextjs_source"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            map_paths = ['/_next/static/chunks/pages/', '/_next/static/']
            for base_path in map_paths:
                try:
                    resp = await client.get(f"{base_url}{base_path}", headers=req.get("headers", {}))
                    for pattern, desc in ERROR_PATTERNS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Next.js Source Maps Exposed",
                                description=f"{desc}. Next.js source maps (.map files) are publicly accessible, exposing application source code.",
                                evidence=f"Path: {base_path}\nPattern: {pattern}",
                                remediation="Disable source maps in production builds. Use generateSourceMaps: false in next.config.js.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
