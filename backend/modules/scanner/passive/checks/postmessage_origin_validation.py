import re
from modules.scanner.base_check import BaseCheck, CheckResult


class PostmessageOriginValidationCheck(BaseCheck):
    name = "postmessage_origin_validation"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        listener_patterns = [
            r"addEventListener\s*\(\s*['\"]message['\"]\s*,.*\)",
            r"onmessage\s*=\s*function",
            r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*\w+",
        ]
        has_listener = any(re.search(p, body) for p in listener_patterns)
        if not has_listener:
            return results
        if not re.search(r"event\.origin\s*(!==?|===?)\s*['\"]", body):
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="postMessage origin validation missing",
                description="The page listens for postMessage events but does not validate event.origin, allowing any website to send messages.",
                evidence=f"postMessage listener found without origin validation\nBody snippet: {body[:500]}",
                remediation='Always validate event.origin in postMessage event handlers. Compare against a whitelist: if (event.origin !== "https://trusted.com") return;',
                cwe="CWE-668",
            ))
        return results
