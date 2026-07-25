import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscConnectMethodCheck(BaseCheck):
    name = "misc_connect_method"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "GET")).upper()
        if method == "CONNECT":
            path = request_data.get("path", request_data.get("url", ""))
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="CONNECT method enabled",
                description=f"CONNECT method is enabled at {path}. CONNECT allows the server to act as a proxy, which can be abused for tunneling.",
                evidence=f"Path: {path}\nMethod: CONNECT",
                remediation="Disable the CONNECT method unless the server is explicitly intended to be a forward proxy.",
                cwe="CWE-749",
            ))
        return results
