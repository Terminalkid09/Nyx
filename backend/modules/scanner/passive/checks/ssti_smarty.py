import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiSmartyCheck(BaseCheck):
    name = "ssti_smarty"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        if not body:
            return results
        patterns = [
            (r"\{php\}.*\{/php\}", "Smarty {php} tag evaluated"),
            (r"\{literal\}.*\{/literal\}", "Smarty literal block evaluated"),
            (r"\{include\s+file=", "Smarty include directive"),
            (r"\{fetch\s+file=", "Smarty fetch directive"),
            (r"\{math\s+equation=", "Smarty math equation"),
            (r"\{\$smarty\.", "Smarty $smarty variable"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Smarty PHP Server-Side Template Injection",
                    description="Smarty PHP template syntax detected in responses. User input rendered as Smarty template can lead to SSTI and RCE.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input as Smarty templates. Use sandboxed rendering. Prefer template literals over dynamic template strings.",
                    cwe="CWE-1336",
                ))
                break

        return results
