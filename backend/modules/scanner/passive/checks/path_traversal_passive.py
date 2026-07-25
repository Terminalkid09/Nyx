import re
import urllib.parse
from modules.scanner.base_check import BaseCheck, CheckResult

KNOWN_FILE_PATTERNS = [
    r"root:x:0:0:",
    r"\[boot loader\]",
    r"\[extensions\]",
    r"\[fonts\]",
    r"#\s*\$OpenBSD",
    r"#\s*-\*-\s*shell\s*-\*-",
    r"www-data:x:\d+:\d+:",
    r"nobody:x:\d+:\d+:",
    r"daemon:x:\d+:\d+:",
]


class PathTraversalPassiveCheck(BaseCheck):
    name = "path_traversal_passive"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "")
        path = request_data.get("path", "")
        query = request_data.get("query", "")
        body_content = event.get("body", "") or ""
        status = event.get("status")

        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"%2e%2e/",
            r"\.\./\.\./",
            r"\.\.\\\.\.\\",
            r"..;",
            r"..%00",
            r"%252e%252e%252f",
            r"%%32%%65%%32%%65%%32%%66",
        ]

        for pattern in traversal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Path traversal pattern detected in request",
                    description=f"URL contains path traversal sequence '{pattern}'.",
                    evidence=f"URL: {url}\nPattern: {pattern}\nStatus: {status}",
                    remediation="Validate and sanitize all file path inputs. Use a whitelist of allowed files.",
                    cwe="CWE-22",
                ))
                break

        if status == 200 and body_content:
            for known in KNOWN_FILE_PATTERNS:
                if re.search(known, body_content):
                    results.append(CheckResult(
                        triggered=True,
                        severity="critical",
                        title="Path traversal - Known file content detected in response",
                        description="Response body contains content matching known system files, indicating successful path traversal.",
                        evidence=f"Pattern matched: {known}\nStatus: {status}",
                        remediation="Immediately fix path traversal vulnerability. Validate and sanitize all file path inputs.",
                        cwe="CWE-22",
                    ))
                    break

        return results
