import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssInsertadjacenthtmlCheck(BaseCheck):
    name = "xss_insertadjacenthtml"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"insertAdjacentHTML\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"][^'\"]*<", "insertAdjacentHTML with HTML"),
            (r"insertAdjacentHTML\s*\(\s*['\"][^'\"]*['\"]\s*,\s*[^'\"\s]+", "insertAdjacentHTML with variable"),
            (r"insertAdjacentHTML\s*\(\s*['\"][^'\"]*['\"]\s*,\s*.*response", "insertAdjacentHTML from response"),
            (r"insertAdjacentHTML\s*\(\s*['\"][^'\"]*['\"]\s*,\s*.*\.value", "insertAdjacentHTML from input"),
            (r"insertAdjacentHTML\s*\(\s*['\"][^'\"]*['\"]\s*,\s*.*location", "insertAdjacentHTML from location"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS via insertAdjacentHTML",
                    description=f"{desc}. insertAdjacentHTML parses HTML strings and can lead to XSS if user input is included.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Use insertAdjacentText instead of insertAdjacentHTML for text content. Sanitize HTML input.",
                    cwe="CWE-79",
                ))
                break
        return results
