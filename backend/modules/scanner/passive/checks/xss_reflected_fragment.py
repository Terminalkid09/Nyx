import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssReflectedFragmentCheck(BaseCheck):
    name = "xss_reflected_fragment"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        if "#" not in url:
            return results
        fragment = url.split("#", 1)[1] if "#" in url else ""
        if not fragment:
            return results
        body = event.get("response_body", "") or event.get("body", "") or ""
        xss_patterns = [
            r"<script[^>]*>",
            r"onerror\s*=",
            r"onload\s*=",
            r"javascript\s*:",
        ]
        for pattern in xss_patterns:
            match = re.search(pattern, fragment, re.IGNORECASE)
            if match:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Reflected XSS in URL fragment",
                    description=f"URL fragment (#) contains XSS payload: {match.group(0)}. The fragment is accessible via JavaScript and may execute in certain contexts.",
                    evidence=f"Fragment: {fragment}\nPattern: {pattern}\nURL: {url}",
                    remediation="Fragments are client-side only, but ensure no server-side reflection occurs. Use Content-Security-Policy.",
                    cwe="CWE-79",
                ))
                break
        return results
