import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XpathMoreCheck(BaseCheck):
    name = "xpath_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = event.get("url", "") or request_data.get("url", "")
        body = event.get("request_body", "") or ""
        response_body = event.get("response_body", "") or ""
        combined = f"{url} {body} {response_body}"

        xpath_patterns = [
            (r"' or '1'='1", "XPath: ' or '1'='1"),
            (r"' and '1'='1", "XPath: ' and '1'='1"),
            (r"' or 1=1--", "XPath: ' or 1=1--"),
            (r"\]\|\[", "XPath: ]|[ union"),
            (r"/\.\./", "XPath: /../ parent traversal"),
            (r"'\s*or\s+'1'='1", "XPath: ' or '1'='1"),
            (r"'\s*and\s+'1'='1", "XPath: ' and '1'='1"),
            (r"'\s*or\s+1=1", "XPath: ' or 1=1"),
        ]
        for pattern, desc in xpath_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XPath injection variant detected",
                    description=f"{desc} found. XPath injection may allow data extraction.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Escape XPath special characters. Use parameterised XPath queries. Validate and sanitize all user input.",
                    cwe="CWE-643",
                ))
                break
        return results
