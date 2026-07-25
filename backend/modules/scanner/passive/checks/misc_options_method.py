import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscOptionsMethodCheck(BaseCheck):
    name = "misc_options_method"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "GET")).upper()
        if method == "OPTIONS":
            headers = event.get("headers", {}) or {}
            allow = headers.get("allow", headers.get("Allow", ""))
            path = request_data.get("path", request_data.get("url", ""))
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="OPTIONS method enabled",
                description=f"OPTIONS method is enabled at {path}. OPTIONS reveals allowed HTTP methods which can aid attackers.",
                evidence=f"Allow: {allow}\nPath: {path}",
                remediation="Restrict OPTIONS method if not needed, or ensure only necessary methods are advertised.",
                cwe="CWE-749",
            ))
        return results
