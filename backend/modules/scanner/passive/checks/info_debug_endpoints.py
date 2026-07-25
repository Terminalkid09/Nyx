import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoDebugEndpointsCheck(BaseCheck):
    name = "info_debug_endpoints"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        body = event.get("response_body", "") or event.get("body", "") or ""
        status = event.get("status")
        debug_paths = ["/debug", "/debug/", "/console", "/_debug", "/__debug", "/actuator", "/actuator/", "/dev", "/dev/", "/test", "/test/"]
        is_debug_path = any(p == path.lower() or path.lower().startswith(p) for p in debug_paths)
        if is_debug_path and status == 200:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Debug endpoints exposed",
                description=f"Debug/admin endpoint accessible at {path}. Debug endpoints often provide system shells or detailed debugging information.",
                evidence=f"URL: {path}\nStatus: {status}",
                remediation="Remove or secure all debug endpoints in production. Use authentication and network restrictions for development tools.",
                cwe="CWE-200",
            ))
        return results
