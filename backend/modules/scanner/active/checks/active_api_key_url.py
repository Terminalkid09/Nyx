import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveApiKeyUrlCheck(BaseCheck):
    name = "active_api_key_url"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        url = base_request.get("url", "")
        parsed = urlparse(url)
        if parsed.query:
            query_params = parsed.query.lower()
            key_patterns = ['api_key', 'apikey', 'api-key', 'secret', 'token', 'access_token', 'auth', 'password', 'passwd']
            for pattern in key_patterns:
                if pattern in query_params:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="API Key in URL Parameter",
                        description=f"Sensitive parameter '{pattern}' found in URL query string. API keys in URLs are exposed in server logs, browser history, and referrer headers.",
                        evidence=f"URL parameter containing: {pattern}",
                        remediation="Transmit API keys in Authorization headers, not URL parameters. Use POST requests for sensitive data.",
                        cwe="CWE-598",
                    ))
                    break
        return results
