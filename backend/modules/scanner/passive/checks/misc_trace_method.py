import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscTraceMethodCheck(BaseCheck):
    name = "misc_trace_method"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "GET")).upper()
        if method == "TRACE":
            headers = event.get("headers", {}) or {}
            body = event.get("response_body", "") or event.get("body", "") or ""
            path = request_data.get("path", request_data.get("url", ""))
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="TRACE method enabled (Cross-Site Tracing)",
                description=f"TRACE method is enabled at {path}. XST allows attackers to steal cookies and auth headers via JavaScript.",
                evidence=f"Path: {path}\nResponse body: {body[:200]}",
                remediation="Disable the TRACE method on the web server. For Apache: TraceEnable Off. For Nginx: return 405 for TRACE.",
                cwe="CWE-603",
            ))
        return results
