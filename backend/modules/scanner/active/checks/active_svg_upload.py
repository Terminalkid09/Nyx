import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse


SVG_XSS_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script>alert(1)</script>
  <text x="10" y="20">test</text>
</svg>'''


class ActiveSvgUploadCheck(BaseCheck):
    name = "active_svg_upload"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        upload_patterns = [
            r'<form[^>]*action=["\']([^"\']+upload[^"\']*)["\']',
            r'<form[^>]*action=["\']([^"\']+import[^"\']*)["\']',
            r'(?i)enctype=["\']multipart/form-data["\']',
        ]

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            try:
                resp = await client.get(base_url)
                has_upload = any(re.search(p, resp.text) for p in upload_patterns)
                if has_upload:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="Potential SVG Upload",
                        description="File upload endpoint detected. May accept SVG with embedded scripts.",
                        evidence=f"URL: {base_url}\nUpload form detected",
                        remediation="Validate SVG files: strip scripts, use allowlist of safe tags, serve with Content-Type: text/plain for raw SVGs.",
                        cwe="CWE-79",
                    ))
            except Exception:
                pass

            upload_paths = ["/upload", "/uploads", "/api/upload", "/file/upload"]
            for path in upload_paths:
                try:
                    files = {"file": ("payload.svg", SVG_XSS_PAYLOAD.encode(), "image/svg+xml")}
                    resp = await client.post(f"{base_url}{path}", files=files)
                    if resp.status_code in (200, 201, 302):
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="SVG Upload Accepted",
                            description=f"SVG file upload accepted at '{path}' (status {resp.status_code}).",
                            evidence=f"URL: {base_url}{path}\nStatus: {resp.status_code}",
                            remediation="Validate file content. Reject SVGs with <script> or event handlers. Only allow safe image formats.",
                            cwe="CWE-79",
                        ))
                except Exception:
                    continue
        return results
