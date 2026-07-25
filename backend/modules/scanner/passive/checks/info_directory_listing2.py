import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoDirectoryListing2Check(BaseCheck):
    name = "info_directory_listing2"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        signatures = [
            (r"<title>Index of /", "Apache-style directory listing"),
            (r"<h1>Index of /", "Apache index page"),
            (r"\[parent directory\]", "Parent directory link"),
            (r"<a href=\"\?C=N;O=D\">Name</a>", "Apache sorted listing"),
            (r"Directory listing for", "Generic directory listing"),
            (r"Last modified\s+Size\s+Description", "Directory listing header"),
            (r"<A HREF=\"\?C=N;O=D\">Name</A>", "Apache uppercase listing"),
        ]
        for pattern, desc in signatures:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Directory listing enabled",
                    description=f"{desc}. Directory browsing is enabled, revealing the file structure of the web server.",
                    evidence=f"Pattern: {pattern}\nBody snippet: {body[:500]}",
                    remediation="Disable directory listing in web server configuration. For Apache: Options -Indexes. For Nginx: autoindex off.",
                    cwe="CWE-548",
                ))
                break
        return results
