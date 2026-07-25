import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SmugglingTeTeCheck(BaseCheck):
    name = "smuggling_te_te"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        te = headers_lower.get("transfer-encoding", "")
        if te:
            te_values = [t.strip().lower() for t in te.split(",")]
            if "chunked" in te_values:
                obfuscated = [v for v in te_values if v != "chunked" and v != ""]
                if obfuscated:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="TE.TE obfuscated smuggling detected",
                        description=f"Transfer-Encoding header contains obfuscated values: '{', '.join(obfuscated)}'. Front-end and back-end may disagree on which Transfer-Encoding value to use.",
                        evidence=f"Transfer-Encoding: {te}",
                        remediation="Reject requests with obfuscated or non-standard Transfer-Encoding values. Ensure consistent parsing between proxies.",
                        cwe="CWE-444",
                    ))
        return results
