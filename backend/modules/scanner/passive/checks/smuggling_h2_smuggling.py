import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingH2SmugglingCheck(BaseCheck):
    name = "smuggling_h2_smuggling"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        connection = headers_lower.get("connection", "")
        upgrade = headers_lower.get("upgrade", "")
        h2c = headers_lower.get("http2-settings", "")
        if "upgrade" in connection.lower() and "h2c" in upgrade.lower():
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="HTTP/2 request smuggling via h2c upgrade",
                description="HTTP/2 cleartext (h2c) upgrade request detected. HTTP/2 downgrade smuggling can bypass security controls.",
                evidence=f"Connection: {connection}\nUpgrade: {upgrade}\nHTTP2-Settings: {h2c}",
                remediation="Disable HTTP/2 cleartext (h2c) upgrade on front-end servers. Use proper HTTP/2 termination.",
                cwe="CWE-444",
            ))
        return results
