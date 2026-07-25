import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MethodOverrideCheck(BaseCheck):
    name = "method_override"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        override_headers = [
            "x-http-method-override",
            "x-http-method",
            "x-method-override",
        ]
        for h in override_headers:
            if h in headers_lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="HTTP method override header detected",
                    description=f"Header '{h}' found with value '{headers_lower[h]}'. Method override headers can bypass access controls.",
                    evidence=f"Header: {h}: {headers_lower[h]}",
                    remediation="Disable HTTP method override headers if not needed. Validate the overridden method against access controls.",
                    cwe="CWE-284",
                ))
        return results
