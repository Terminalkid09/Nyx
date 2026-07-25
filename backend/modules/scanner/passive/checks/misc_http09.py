import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscHttp09Check(BaseCheck):
    name = "misc_http09"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        status = event.get("status")
        http_version = request_data.get("http_version", event.get("http_version", ""))
        if http_version and "0.9" in http_version:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="HTTP/0.9 support",
                description=f"HTTP/0.9 request detected. HTTP/0.9 has no headers, no status codes, and no security controls.",
                evidence=f"HTTP version: {http_version}\nStatus: {status}",
                remediation="Disable HTTP/0.9 support on the web server. HTTP/0.9 lacks all security features of modern HTTP.",
                cwe="CWE-200",
            ))
        return results
