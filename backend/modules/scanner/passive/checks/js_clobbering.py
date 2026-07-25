import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JsClobberingCheck(BaseCheck):
    name = "js_clobbering"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or ""
        if not body:
            return results

        js_clobber_patterns = [
            (r"document\.write\s*\([\"']<script", "document.write with script injection"),
            (r"innerHTML\s*=\s*[\"'].*?<script", "innerHTML assignment with script tag"),
            (r"outerHTML\s*=\s*[\"'].*?<script", "outerHTML assignment with script tag"),
            (r"insertAdjacentHTML\s*\([\"'].*?<script", "insertAdjacentHTML with script tag"),
            (r"\.innerHTML\s*\+?=\s*[\"'].*?<", "innerHTML concatenation with HTML tags"),
            (r"eval\s*\(\s*[\"'].*?<script", "eval() with script content"),
            (r"setTimeout\s*\(\s*[\"'].*?<script", "setTimeout with script content"),
            (r"setInterval\s*\(\s*[\"'].*?<script", "setInterval with script content"),
        ]
        for pattern, desc in js_clobber_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="JavaScript clobbering detected",
                    description=f"{desc} found. JavaScript clobbering can lead to XSS or unexpected behavior.",
                    evidence=f"Pattern: {pattern}\nResponse snippet: {body[:500]}",
                    remediation="Avoid using innerHTML, outerHTML, and document.write with user-controlled data. Use textContent or createTextNode instead.",
                    cwe="CWE-79",
                ))
                break
        return results
