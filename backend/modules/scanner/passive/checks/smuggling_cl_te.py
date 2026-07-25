import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingClTeCheck(BaseCheck):
    name = "smuggling_cl_te"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        cl = headers_lower.get("content-length", "")
        te = headers_lower.get("transfer-encoding", "")
        if cl and te and "chunked" in te.lower():
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="CL.TE request smuggling detected",
                description="Both Content-Length and Transfer-Encoding: chunked headers present. Front-end may use Content-Length while back-end uses Transfer-Encoding (CL.TE smuggling).",
                evidence=f"Content-Length: {cl}\nTransfer-Encoding: {te}",
                remediation="Ensure consistent parsing of Content-Length and Transfer-Encoding between front-end and back-end servers. Use HTTP/2 to eliminate ambiguity.",
                cwe="CWE-444",
            ))
        return results
