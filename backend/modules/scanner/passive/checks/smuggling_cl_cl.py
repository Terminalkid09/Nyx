import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingClClCheck(BaseCheck):
    name = "smuggling_cl_cl"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        cl = headers_lower.get("content-length", "")
        if cl and "," in cl:
            cl_values = [c.strip() for c in cl.split(",")]
            unique_vals = list(set(cl_values))
            if len(unique_vals) > 1:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="CL.CL request smuggling detected",
                    description=f"Multiple Content-Length headers with different values: {unique_vals}. Servers may interpret different values leading to request smuggling.",
                    evidence=f"Content-Length: {cl}",
                    remediation="Reject requests with multiple Content-Length headers or ensure all proxies use consistent Content-Length parsing.",
                    cwe="CWE-444",
                ))
        return results
