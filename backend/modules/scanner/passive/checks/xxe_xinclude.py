import re
from modules.scanner.base_check import BaseCheck, CheckResult


class XxeXincludeCheck(BaseCheck):
    name = "xxe_xinclude"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("request_body", "") or event.get("body", "") or ""
        if not body:
            return results
        patterns = [
            (r"<xi:include\s+xmlns:xi\s*=\s*[\"']http://www\.w3\.org/2001/XInclude[\"']", "XInclude namespace declared"),
            (r"<xi:include\s+[^>]*parse\s*=\s*[\"']xml[\"']", "XInclude with XML parse"),
            (r"<xi:include\s+[^>]*href\s*=\s*[\"']file://", "XInclude href pointing to file:"),
            (r"<xi:include\s+[^>]*href\s*=\s*[\"']http://", "XInclude href pointing to HTTP"),
            (r"<xi:include\s+[^>]*href\s*=\s*[\"']php://", "XInclude href pointing to PHP stream"),
            (r"<xi:include\s+[^>]*xpointer\s*=", "XInclude with xpointer attribute"),
        ]
        for pattern, desc in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="XXE via XInclude",
                    description=f"{desc}. XInclude allows including external XML content, bypassing DTD-based XXE protections.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:500]}",
                    remediation="Disable XInclude processing in your XML parser if not needed. XInclude can read files even when DTDs are disabled.",
                    cwe="CWE-611",
                ))
                break
        return results
