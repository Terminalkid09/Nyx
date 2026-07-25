import re
from modules.scanner.base_check import BaseCheck, CheckResult


class ServerSideIncludesCheck(BaseCheck):
    name = "server_side_includes"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""

        ssi_patterns = [
            (r"<!--#include\s+(virtual|file)\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #include directive"),
            (r"<!--#echo\s+var\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #echo directive"),
            (r"<!--#exec\s+(cmd|cgi)\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #exec directive (command execution)"),
            (r"<!--#set\s+var\s*=\s*[\"'][^\"']+[\"']\s+value\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #set directive"),
            (r"<!--#printenv\s*-->",
             "SSI #printenv directive"),
            (r"<!--#config\s+timefmt\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #config directive"),
            (r"<!--#fsize\s+(virtual|file)\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #fsize directive"),
            (r"<!--#flastmod\s+(virtual|file)\s*=\s*[\"'][^\"']+[\"']\s*-->",
             "SSI #flastmod directive"),
            (r"<!--#include\s+file\s*=\s*[\"']/?etc/passwd[\"']\s*-->",
             "SSI #include with /etc/passwd (exploit attempt)"),
        ]

        for pattern, title in ssi_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                results.append(CheckResult(
                    triggered=True,
                    severity="high" if "exploit" in title or "exec" in title else "medium",
                    title=f"Server-Side Include (SSI) directive found: {title}",
                    description="The response body contains an SSI directive, indicating server-side includes may be processed.",
                    evidence=match.group(0)[:300],
                    remediation="Disable SSI (mod_include) if not needed. If required, restrict to trusted content and disable #exec.",
                    cwe="CWE-96",
                ))

        return results
