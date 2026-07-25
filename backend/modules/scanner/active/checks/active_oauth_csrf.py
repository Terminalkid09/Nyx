from urllib.parse import urlparse, parse_qs
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveOauthCsrfCheck(BaseCheck):
    name = "active_oauth_csrf"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        url = base_request.get("url", "")
        params = parse_qs(urlparse(url).query)
        if 'response_type' in params and 'state' not in params:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="OAuth CSRF - Missing State Parameter",
                description="OAuth authorization request includes response_type but no state parameter, making it vulnerable to CSRF attacks on the authorization callback.",
                evidence="Missing state parameter in OAuth request",
                remediation="Always include and validate a cryptographically random state parameter in OAuth authorization requests.",
                cwe="CWE-352",
            ))
        return results
