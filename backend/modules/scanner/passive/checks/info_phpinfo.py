import re
from modules.scanner.base_check import BaseCheck, CheckResult


class InfoPhpinfoCheck(BaseCheck):
    name = "info_phpinfo"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        body = event.get("response_body", "") or event.get("body", "") or ""
        status = event.get("status")
        is_phpinfo = "phpinfo" in path.lower() or "php_info" in path.lower()
        if is_phpinfo and status == 200:
            phpinfo_signatures = ["PHP Version", "PHP License", "PHP Credits", "System ", "Build Date ", "Configure Command", "Loaded Configuration File"]
            matches = sum(1 for s in phpinfo_signatures if s in body)
            if matches >= 2:
                results.append(CheckResult(
                    triggered=True,
                    severity="critical",
                    title="phpinfo() exposed",
                    description=f"phpinfo() output is publicly accessible at {path}. This reveals PHP configuration, environment variables, and installed extensions.",
                    evidence=f"URL: {path}\nStatus: {status}\nMatches: {matches}",
                    remediation="Remove phpinfo() files from production. Disable functions that expose system configuration information.",
                    cwe="CWE-200",
                ))
        return results
