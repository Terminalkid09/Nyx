import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssPostmessageCheck(BaseCheck):
    name = "xss_postmessage"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"addEventListener\s*\(\s*['\"]message['\"]", "postMessage listener registered"),
            (r"onmessage\s*=", "onmessage handler assigned"),
        ]
        has_listener = False
        for pattern, desc in patterns:
            if re.search(pattern, body):
                has_listener = True
                break
        if not has_listener:
            return results
        unsafe_patterns = [
            r"eval\s*\(\s*event\.data",
            r"\.innerHTML\s*=\s*event\.data",
            r"\.outerHTML\s*=\s*event\.data",
            r"document\.write\s*\(\s*event\.data",
            r"new\s+Function\s*\(\s*event\.data",
            r"setTimeout\s*\(\s*event\.data",
            r"setInterval\s*\(\s*event\.data",
            r"insertAdjacentHTML\s*\(\s*.*event\.data",
            r"src\s*=\s*event\.data",
        ]
        for pattern in unsafe_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via postMessage - unsafe handling of message data",
                    description="The page listens for postMessage events and unsafely uses event.data in a potentially dangerous sink.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Validate the origin of messages using event.origin. Sanitize event.data before using it in DOM operations.",
                    cwe="CWE-79",
                ))
                break
        return results
