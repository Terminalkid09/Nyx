import re
from modules.scanner.base_check import BaseCheck, CheckResult


class DirectoryListingCheck(BaseCheck):
    name = "directory_listing"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        status = event.get("status")
        content_type = (event.get("headers", {}) or {}).get("content-type", "")

        if "text/html" not in content_type:
            return results

        listing_patterns = [
            r"Index\s+of\s+/?",
            r"Parent\s+Directory</a>",
            r"Directory\s+Listing\s+for",
            r"<title>Index\s+of\s+[/\w.-]*</title>",
            r"\[To\s+Parent\s+Directory\]",
            r"<h1>Directory\s+listings?\s+for\s+",
            r"<A\s+HREF=\"\?C=N;O=D\">Name</A>",
            r"<a\s+href=\"\?C=N;O=D\">Name</a>",
        ]

        for pattern in listing_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                path = request_data.get("path", request_data.get("url", ""))
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Directory listing enabled",
                    description=f"Directory listing is enabled at {path}, revealing file/folder structure.",
                    evidence=f"URL: {path}\nStatus: {status}",
                    remediation="Disable directory listing in your web server configuration (e.g., Options -Indexes for Apache, autoindex off for Nginx).",
                    cwe="CWE-548",
                ))
                break

        return results
