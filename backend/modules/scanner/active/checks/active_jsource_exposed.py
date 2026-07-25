import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


class ActiveJsourceExposedCheck(BaseCheck):
    name = "active_jsource_exposed"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            source_paths = ["/js/", "/static/js/", "/assets/js/", "/dist/js/"]
            for path in source_paths:
                try:
                    resp = await client.get(f"{base_url}{path}")
                    if resp.status_code == 200 and "text/html" not in resp.headers.get("content-type", ""):
                        js_files = re.findall(r'(?:src|href)="([^"]+\.js[^"]*)"', resp.text)
                        for js in js_files[:5]:
                            if js.startswith("/"):
                                js_url = f"{base_url}{js}"
                                try:
                                    js_resp = await client.get(js_url)
                                    if "api" in js_resp.text.lower() and ("key" in js_resp.text.lower() or "secret" in js_resp.text.lower() or "token" in js_resp.text.lower()):
                                        results.append(CheckResult(
                                            triggered=True,
                                            severity="high",
                                            title="Sensitive Data in JavaScript",
                                            description=f"JavaScript file '{js}' may contain API keys or tokens.",
                                            evidence=f"JS URL: {js_url}\nSize: {len(js_resp.content)} bytes",
                                            remediation="Remove secrets from client-side code. Use server-side proxies for API calls.",
                                            cwe="CWE-312",
                                        ))
                                except Exception:
                                    continue
                except Exception:
                    continue
        return results
