import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiVelocityCheck(BaseCheck):
    name = "ssti_velocity"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\$\{7\*7\}", "Velocity: ${7*7} expression"),
            (r"\$\{class\}", "Velocity: ${class} reference"),
            (r"\$\{request\}", "Velocity: ${request} object"),
            (r"\$\{response\}", "Velocity: ${response} object"),
            (r"\$\{session\}", "Velocity: ${session} object"),
            (r"\$\{application\}", "Velocity: ${application} object"),
            (r"\$!\{", "Velocity: $!{} quiet reference"),
            (r"\#set\s*\(\s*\$\w+\s*=", "Velocity: #set directive"),
            (r"\#if\s*\(\s*\$\w+", "Velocity: #if directive"),
            (r"\#foreach\s*\(\s*\$\w+\s+in", "Velocity: #foreach directive"),
            (r"\#include\s*\(\s*['\"]", "Velocity: #include directive"),
            (r"\#parse\s*\(\s*['\"]", "Velocity: #parse directive"),
            (r"\#evaluate\s*\(\s*['\"]", "Velocity: #evaluate directive"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Velocity Server-Side Template Injection",
                    description=f"{desc}. Velocity template directives/expressions are evaluated server-side, indicating SSTI.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input with Velocity. Restrict access to Velocity tools and directives.",
                    cwe="CWE-1336",
                ))
                break
        return results
