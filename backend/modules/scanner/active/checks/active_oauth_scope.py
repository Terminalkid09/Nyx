from urllib.parse import urlparse, parse_qs
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveOauthScopeCheck(BaseCheck):
    name = "active_oauth_scope"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        url = base_request.get("url", "")
        params = parse_qs(urlparse(url).query)
        if 'scope' in params:
            scope_value = params['scope'][0]
            if any(kw in scope_value.lower() for kw in ['admin', '*', 'all', 'full']):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="OAuth Scope Upgrade Potential",
                    description=f"OAuth scope parameter found with value '{scope_value}'. Client-provided scopes may allow privilege escalation.",
                    evidence=f"Scope value: {scope_value}",
                    remediation="Server must validate requested scopes against user authorization. Never rely on client-provided scope values.",
                    cwe="CWE-285",
                ))
        return results
