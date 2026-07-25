import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiJinja2Check(BaseCheck):
    name = "ssti_jinja2"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\{\{7\*7\}\}", "Jinja2: {{7*7}} template expression"),
            (r"\{\{config\}\}", "Jinja2: {{config}} object exposed"),
            (r"\{\{self\}\}", "Jinja2: {{self}} object exposed"),
            (r"\{\{app\.request\}", "Jinja2: {{app.request}} exposed"),
            (r"\{\{''\.__class__", "Jinja2: __class__ introspection"),
            (r"\{\{cycler\.__init__", "Jinja2: cycler.__init__ access"),
            (r"\{\{joiner\.__init__", "Jinja2: joiner.__init__ access"),
            (r"\{\{namespace\.__init__", "Jinja2: namespace.__init__ access"),
            (r"\{\{lipsum\.__globals__", "Jinja2: lipsum.__globals__ access"),
            (r"\{\{range\.__class__", "Jinja2: range.__class__ access"),
            (r"\{\{dict\.__class__", "Jinja2: dict.__class__ access"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Jinja2 Server-Side Template Injection",
                    description=f"{desc}. Jinja2 template expressions are being evaluated server-side, indicating SSTI vulnerability.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not render user input as Jinja2 templates. Use sandboxed template rendering with restricted access.",
                    cwe="CWE-1336",
                ))
                break
        return results
