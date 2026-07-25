import re
from modules.scanner.base_check import BaseCheck, CheckResult


class DomClobberingCheck(BaseCheck):
    name = "dom_clobbering"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        if not body:
            return results

        dom_clobber_patterns = [
            (r"<a\s+[^>]*id\s*=\s*[\"']([^\"']+)[\"'][^>]*>", "Anchor tag with id (DOM clobbering)"),
            (r"<img\s+[^>]*id\s*=\s*[\"']([^\"']+)[\"'][^>]*>", "Image tag with id (DOM clobbering)"),
            (r"<form\s+[^>]*name\s*=\s*[\"']([^\"']+)[\"']", "Form with name attribute (DOM clobbering)"),
            (r"<embed\s+[^>]*name\s*=\s*[\"']([^\"']+)[\"']", "Embed with name attribute (DOM clobbering)"),
            (r"<object\s+[^>]*name\s*=\s*[\"']([^\"']+)[\"']", "Object with name attribute (DOM clobbering)"),
        ]
        for pattern, desc in dom_clobber_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="DOM clobbering detected",
                    description=f"{desc} found. DOM clobbering can overwrite global JavaScript variables.",
                    evidence=f"Pattern: {pattern}\nResponse snippet: {body[:500]}",
                    remediation="Use strict variable scoping. Avoid relying on global DOM elements as variables. Use Content-Security-Policy to restrict inline scripts.",
                    cwe="CWE-79",
                ))
                break
        return results
