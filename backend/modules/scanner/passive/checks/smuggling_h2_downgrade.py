import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingH2DowngradeCheck(BaseCheck):
    name = "smuggling_h2_downgrade"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        protocol = headers_lower.get("x-forwarded-proto", headers_lower.get("x-forwarded-protocol", ""))
        if protocol == "h2" or protocol == "http/2":
            transfer_encoding = headers_lower.get("transfer-encoding", "")
            content_length = headers_lower.get("content-length", "")
            if transfer_encoding or content_length:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="HTTP/2 downgrade smuggling detected",
                    description="HTTP/2 request is downgraded to HTTP/1.1 with HTTP/1.1 headers present. This can enable HTTP/2 downgrade request smuggling.",
                    evidence=f"Protocol: {protocol}\nTransfer-Encoding: {transfer_encoding}\nContent-Length: {content_length}",
                    remediation="Disable HTTP/2 downgrade to HTTP/1.1 on reverse proxies. Ensure consistent protocol handling end-to-end.",
                    cwe="CWE-444",
                ))
        return results
