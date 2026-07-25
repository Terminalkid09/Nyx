import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoServerStatusCheck(BaseCheck):
    name = "info_server_status"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        body = event.get("response_body", "") or event.get("body", "") or ""
        status = event.get("status")
        server_status_paths = ["/server-status", "/server-info", "/status", "/health", "/metrics", "/actuator/health", "/actuator/info"]
        is_status_path = any(p in path.lower() for p in server_status_paths)
        if is_status_path and status == 200:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="Server status page exposed",
                description=f"Server status/monitoring page exposed at {path}. These pages leak server performance data, request metrics, and configuration hints.",
                evidence=f"URL: {path}\nStatus: {status}\nBody snippet: {body[:300]}",
                remediation="Restrict access to server status and monitoring pages to internal networks only. Disable in production or require authentication.",
                cwe="CWE-200",
            ))
        return results
