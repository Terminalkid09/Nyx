import re
from modules.scanner.base_check import BaseCheck, CheckResult


class Http2DowngradeCheck(BaseCheck):
    name = "http2_downgrade"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        http2_headers = [
            "x-http2-stream-id",
            "x-http2-priority",
            "http2-settings",
            "upgrade",
        ]
        for h in http2_headers:
            if h in headers_lower:
                results.append(CheckResult(
                    triggered=True,
                    severity="low",
                    title="HTTP/2 to HTTP/1.1 downgrade detected",
                    description=f"Header '{h}' indicates HTTP/2 to HTTP/1.1 protocol downgrade. This may expose the application to downgrade attacks.",
                    evidence=f"Header: {h}: {headers_lower[h]}",
                    remediation="Ensure consistent HTTP protocol version handling. Disable HTTP/1.1 downgrade if HTTP/2 is supported.",
                    cwe="CWE-272",
                ))
                break
        return results
