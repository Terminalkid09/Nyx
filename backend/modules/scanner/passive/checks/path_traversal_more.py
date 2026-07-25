import re
from modules.scanner.base_check import BaseCheck, CheckResult


class PathTraversalMoreCheck(BaseCheck):
    name = "path_traversal_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        url = event.get("url", "") or request_data.get("url", "")
        combined = f"{url} {body}"

        pt_patterns = [
            (r"\.\./\.\./", "Basic path traversal (../)"),
            (r"\.\.\\\.\.\\", "Windows path traversal (..\\)"),
            (r"%2e%2e%2f", "URL-encoded path traversal (%2e%2e%2f)"),
            (r"%252e%252e%252f", "Double URL-encoded path traversal"),
            (r"\.\.%252f", "Double-encoded dot-dot-slash"),
            (r"%c0%ae%c0%ae/", "Unicode overlong path traversal"),
            (r"%c0%ae%c0%ae%c0%af", "Unicode overlong encoded slash"),
            (r"\.\.\\", "Windows path traversal (..\\)"),
            (r"\.\.%5c", "URL-encoded Windows path traversal"),
            (r"\.\.;/", "Unicode normalization path traversal"),
        ]
        for pattern, desc in pt_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Path traversal variant detected",
                    description=f"{desc} found. Path traversal may allow reading arbitrary files.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Validate file paths against an allowlist. Use a chroot jail or sandbox. Normalize paths before validation.",
                    cwe="CWE-22",
                ))
                break
        return results
