import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssMetaRefreshCheck(BaseCheck):
    name = "xss_meta_refresh"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r'<meta[^>]*http-equiv\s*=\s*["\']?\s*refresh\s*["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*javascript',
             "Meta refresh with javascript: URL"),
            (r'<meta[^>]*http-equiv\s*=\s*["\']?\s*refresh\s*["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*data:',
             "Meta refresh with data: URL"),
            (r'<meta[^>]*http-equiv\s*=\s*["\']?\s*refresh\s*["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*vbscript',
             "Meta refresh with vbscript: URL"),
            (r'<meta[^>]*http-equiv\s*=\s*["\']?\s*refresh\s*["\']?[^>]*content\s*=\s*["\'][^"\']*url\s*=\s*[^"\'<>]*\$\{',
             "Meta refresh with template literal injection"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS in meta refresh URL",
                    description=f"{desc}. Meta refresh with a javascript: or data: URL can execute JavaScript.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Avoid using meta refresh with user-controlled URL values. If needed, validate the URL scheme.",
                    cwe="CWE-79",
                ))
                break
        return results
