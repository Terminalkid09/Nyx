import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingTeClCheck(BaseCheck):
    name = "smuggling_te_cl"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        cl = headers_lower.get("content-length", "")
        te = headers_lower.get("transfer-encoding", "")
        if cl and te and "chunked" in te.lower():
            if "transfer-encoding" in headers_lower:
                te_count = len(headers_lower["transfer-encoding"].split(","))
                if te_count >= 2:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="TE.CL request smuggling detected",
                        description="Transfer-Encoding header appears multiple times. Front-end may use Transfer-Encoding while back-end uses Content-Length (TE.CL smuggling).",
                        evidence=f"Content-Length: {cl}\nTransfer-Encoding: {te}",
                        remediation="Reject requests with multiple Transfer-Encoding headers. Use HTTP/2 which eliminates these ambiguities.",
                        cwe="CWE-444",
                    ))
        return results
