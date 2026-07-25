import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingContentLengthCheck(BaseCheck):
    name = "smuggling_content_length"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        cl = headers_lower.get("content-length", "")
        te = headers_lower.get("transfer-encoding", "")
        if cl and te:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Content-Length with Transfer-Encoding (HTTP Smuggling)",
                description="Both Content-Length and Transfer-Encoding headers present in the response, which can lead to HTTP request smuggling via parser differentials.",
                evidence=f"Content-Length: {cl}, Transfer-Encoding: {te}",
                remediation="Remove duplicate or conflicting Content-Length/Transfer-Encoding headers. Use HTTP/2 which eliminates header ambiguity.",
                cwe="CWE-444",
            ))

        return results
