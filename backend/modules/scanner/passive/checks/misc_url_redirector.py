import re
from modules.scanner.base_check import BaseCheck, CheckResult


class MiscUrlRedirectorCheck(BaseCheck):
    name = "misc_url_redirector"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        if not url:
            return results
        redirect_params = ["redirect", "url", "next", "return", "return_to", "return_url", "target", "dest", "destination", "out", "view", "dir", "file", "load", "path", "continue", "window", "open", "callback", "referer", "reference", "src", "nav", "page", "host", "port", "domain", "to", "link", "goto", "logout", "done", "success", "fail"]
        for param in redirect_params:
            pattern = rf"[?&]{param}\s*=\s*[^&]+"
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                value = match.group(0).split("=", 1)[1] if "=" in match.group(0) else ""
                if value and re.match(r"https?://", value, re.IGNORECASE):
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="URL redirector abuse",
                        description=f"URL parameter '{param}' contains '{value[:100]}'. Open URL redirectors can be used in phishing attacks.",
                        evidence=f"Parameter: {param}\nValue: {value[:200]}\nURL: {url}",
                        remediation="Validate and whitelist redirect destinations. Use a mapping of named redirect targets instead of arbitrary URLs.",
                        cwe="CWE-601",
                    ))
                    break
        return results
