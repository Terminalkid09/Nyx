import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssMoreVariantsCheck(BaseCheck):
    name = "xss_more_variants"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        if not body:
            return results

        xss_patterns = [
            (r"<script[^>]*>.*?</script>", "Script tag injection"),
            (r"onerror\s*=\s*['\"]?[^'\"\s>]+", "onerror event handler"),
            (r"onload\s*=\s*['\"]?[^'\"\s>]+", "onload event handler"),
            (r"onfocus\s*=\s*['\"]?[^'\"\s>]+", "onfocus event handler"),
            (r"onmouseover\s*=\s*['\"]?[^'\"\s>]+", "onmouseover event handler"),
            (r"onsubmit\s*=\s*['\"]?[^'\"\s>]+", "onsubmit event handler"),
            (r"src\s*=\s*[\"']javascript:", "src=javascript: XSS"),
            (r"src\s*=\s*[\"']data:", "src=data: XSS"),
            (r"href\s*=\s*[\"']vbscript:", "vbscript: XSS in href"),
            (r"href\s*=\s*[\"']javascript:", "javascript: XSS in href"),
            (r"expression\s*\(", "CSS expression() XSS"),
            (r"import\s*\([\"']javascript:", "import() with javascript: XSS"),
            (r"<svg\s+[^>]*onload\s*=", "SVG onload XSS"),
            (r"<math\s+[^>]*onload\s*=", "MathML onload XSS"),
            (r"<iframe\s+[^>]*srcdoc\s*=", "iframe srcdoc XSS"),
        ]
        for pattern, desc in xss_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XSS variant detected",
                    description=f"{desc} found in response. This XSS variant may execute in the browser.",
                    evidence=f"Pattern: {pattern}\nResponse snippet: {body[:500]}",
                    remediation="Encode output based on context. Use Content-Security-Policy. Validate and sanitize all user input.",
                    cwe="CWE-79",
                ))
                break
        return results
