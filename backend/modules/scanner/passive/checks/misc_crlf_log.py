import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscCrlfLogCheck(BaseCheck):
    name = "misc_crlf_log"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        headers = request_data.get("headers", {}) or {}
        combined = url + str(dict(headers))
        crlf_patterns = [
            (r"%0d%0a", "CRLF injection via %0d%0a encoding"),
            (r"%0a%0d", "CRLF injection via %0a%0d encoding"),
            (r"\r\n", "Raw CRLF sequence"),
            (r"%0d", "CR character (%0d) injection"),
            (r"%0a", "LF character (%0a) injection"),
        ]
        for pattern, desc in crlf_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="CRLF injection in log",
                    description=f"{desc} detected in request. CRLF injection in log entries can forge log entries or exploit log viewers.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Sanitize or reject newline characters in log input. Use structured logging (JSON) instead of plain text logs.",
                    cwe="CWE-117",
                ))
                break
        return results
