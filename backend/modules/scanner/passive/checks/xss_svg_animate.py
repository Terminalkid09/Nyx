import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XssSvgAnimateCheck(BaseCheck):
    name = "xss_svg_animate"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"<animate[^>]*attributeName\s*=", "SVG animate tag present"),
            (r"<animateTransform[^>]*>", "SVG animateTransform tag present"),
            (r"<set[^>]*attributeName\s*=\s*['\"]onbegin['\"]", "SVG set with onbegin attribute"),
            (r"<animate[^>]*onbegin\s*=", "SVG animate onbegin handler"),
            (r"<animate[^>]*onend\s*=", "SVG animate onend handler"),
            (r"<animate[^>]*onrepeat\s*=", "SVG animate onrepeat handler"),
            (r"<animateTransform[^>]*onbegin\s*=", "SVG animateTransform onbegin"),
            (r"<set[^>]*onbegin\s*=", "SVG set onbegin event"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="XSS via SVG animate elements",
                    description=f"{desc}. SVG animation elements with event handlers (onbegin, onend, onrepeat) can execute JavaScript.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Sanitize SVG content to remove event handler attributes from animation elements. Use CSP to block inline scripts.",
                    cwe="CWE-79",
                ))
                break
        return results
