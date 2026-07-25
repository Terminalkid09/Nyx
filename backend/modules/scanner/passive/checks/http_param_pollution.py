import re
from urllib.parse import urlparse, parse_qs
from modules.scanner.base_check import BaseCheck, CheckResult


class HttpParamPollutionCheck(BaseCheck):
    name = "http_param_pollution"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = event.get("url", "") or request_data.get("url", "")
        if not url:
            return results

        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param, values in params.items():
            if len(values) > 1:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="HTTP parameter pollution detected",
                    description=f"Parameter '{param}' appears multiple times in the URL. This may indicate HTTP parameter pollution (HPP).",
                    evidence=f"Parameter: {param}\nValues: {values}\nURL: {url}",
                    remediation="Use the first or last value consistently. Validate and reject duplicate parameters if not expected.",
                    cwe="CWE-235",
                ))
        return results
