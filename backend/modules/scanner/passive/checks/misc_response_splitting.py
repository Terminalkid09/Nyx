import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscResponseSplittingCheck(BaseCheck):
    name = "misc_response_splitting"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        headers = request_data.get("headers", {}) or {}
        combined = url + str(dict(headers))
        split_patterns = [
            (r"%0d%0aContent-Length:", "CRLF with Content-Length injection"),
            (r"%0d%0aHTTP/1", "CRLF with HTTP response splitting"),
            (r"%0d%0aSet-Cookie:", "CRLF with Set-Cookie injection"),
            (r"%0d%0aLocation:", "CRLF with Location header injection"),
            (r"\r\nHTTP/1", "Raw CRLF HTTP response splitting"),
            (r"\r\nContent-Length:", "Raw CRLF Content-Length injection"),
        ]
        for pattern, desc in split_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="critical",
                    title="Response splitting",
                    description=f"{desc}. Response splitting allows injecting arbitrary HTTP responses, enabling cache poisoning and XSS.",
                    evidence=f"Pattern: {pattern}\nURL: {url}",
                    remediation="Reject user input containing CRLF sequences. Use libraries that properly encode output for HTTP headers.",
                    cwe="CWE-113",
                ))
                break
        return results
