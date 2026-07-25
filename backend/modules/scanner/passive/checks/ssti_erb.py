import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiErbCheck(BaseCheck):
    name = "ssti_erb"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"<%= 7\*7 %>", "ERB: <%= 7*7 %> expression"),
            (r"<%= system\(", "ERB: <%= system() %> code execution"),
            (r"<%= `.*` %>", "ERB: <%= backtick %> command execution"),
            (r"<%= IO\.", "ERB: <%= IO.* %> file access"),
            (r"<%= File\.", "ERB: <%= File.* %> file access"),
            (r"<% system\(", "ERB: <% system() %> execution"),
            (r"<% `.*` %>", "ERB: <% backtick %> execution"),
            (r"<% File\.", "ERB: <% File.* %> file access"),
            (r"<%= \w+\.inspect %>", "ERB: <%= .inspect %> dump"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="ERB (Ruby) Server-Side Template Injection",
                    description=f"{desc}. ERB template expressions evaluated server-side, indicating SSTI with potential code execution.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input as ERB templates. ERB can execute arbitrary Ruby code.",
                    cwe="CWE-1336",
                ))
                break
        return results
