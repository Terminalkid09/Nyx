import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscHostHeaderPasswordResetCheck(BaseCheck):
    name = "misc_host_header_password_reset"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        headers = event.get("headers", {}) or {}
        req_headers = request_data.get("headers", {}) or {}
        password_reset_keywords = ["reset", "forgot", "password", "recover", "newpassword", "changepassword"]
        is_reset = any(k in path.lower() for k in password_reset_keywords)
        if is_reset:
            host = req_headers.get("host", req_headers.get("Host", ""))
            location = headers.get("location", headers.get("Location", ""))
            if host and location and host.lower() not in location.lower():
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Host header injection via password reset",
                    description=f"Password reset endpoint at '{path}' with Host '{host}' redirects to '{location}'. Host header injection in password reset can redirect reset links to attacker domains.",
                    evidence=f"Path: {path}\nHost: {host}\nLocation: {location}",
                    remediation="Never trust the Host header for generating password reset URLs. Use a configured base URL or validate the Host header against an allowlist.",
                    cwe="CWE-601",
                ))
        return results
