import re
from modules.scanner.base_check import BaseCheck, CheckResult


class SstiMakoCheck(BaseCheck):
    name = "ssti_mako"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"\$\{7\*7\}", "Mako: ${7*7} expression"),
            (r"\$\{self\}", "Mako: ${self} object"),
            (r"\$\{context\}", "Mako: ${context} object"),
            (r"\$\{request\}", "Mako: ${request} object"),
            (r"\$\{session\}", "Mako: ${session} object"),
            (r"\$\{\w+\.__class__\}", "Mako: __class__ access"),
            (r"\$\{\w+\.__init__\}", "Mako: __init__ access"),
            (r"\$\{\w+\.__globals__\}", "Mako: __globals__ access"),
            (r"<\%\s*include\s+file\s*=\s*['\"]", "Mako: <%include file> directive"),
            (r"\$\{importlib\}", "Mako: importlib access"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Mako Server-Side Template Injection",
                    description=f"{desc}. Mako template expressions evaluated server-side, indicating SSTI.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Do not pass user input to Mako template rendering. Mako templates have access to Python builtins.",
                    cwe="CWE-1336",
                ))
                break
        return results
