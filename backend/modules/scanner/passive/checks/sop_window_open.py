import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SopWindowOpenCheck(BaseCheck):
    name = "sop_window_open"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"window\.open\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]_blank['\"]\s*,\s*['\"][^'\"]*['\"]", "window.open with _blank and features"),
            (r"window\.open\s*\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]\w+['\"]\)", "window.open with custom window name"),
            (r"window\.open\s*\([^)]*noopener", "window.open lacks noopener"),
            (r"window\.open\s*\([^)]*noreferrer", "window.open without noreferrer"),
            (r"window\.open\s*\(\s*url\s*,\s*['\"]_blank['\"]", "window.open with URL variable, noopener may be missing"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="SOP bypass via window.open",
                    description=f"{desc}. window.opener allows the opened window to access the opener's window object, which can leak cross-origin data.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation='Add "noopener,noreferrer" to window.open features. Use rel="noopener" for anchor tags with target="_blank".',
                    cwe="CWE-668",
                ))
                break
        return results
