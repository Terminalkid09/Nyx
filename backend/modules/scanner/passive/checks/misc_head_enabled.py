import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscHeadEnabledCheck(BaseCheck):
    name = "misc_head_enabled"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"HEAD|head", "HEAD method available"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="info",
                    title="HTTP HEAD Method Enabled",
                    description="The HEAD method is enabled on the server. While legitimate, it can be used for fingerprinting and discovery.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Disable HEAD method if not required. Ensure HEAD responses mirror GET responses exactly without body.",
                    cwe="CWE-200",
                ))
                break

        return results
