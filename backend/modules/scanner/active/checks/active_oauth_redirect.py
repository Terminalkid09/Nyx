import httpx
from urllib.parse import urlparse, parse_qs
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveOauthRedirectCheck(BaseCheck):
    name = "active_oauth_redirect"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        url = base_request.get("url", "")
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if 'redirect_uri' in params or 'redirect' in params or 'callback' in params:
            for param in ['redirect_uri', 'redirect', 'callback']:
                if param in params:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="OAuth Redirect URI Parameter Detected",
                        description=f"OAuth parameter '{param}' found in URL. Redirect URIs should be strictly validated against a whitelist.",
                        evidence=f"Parameter: {param}, Value: {params[param][0]}",
                        remediation="Strictly validate redirect_uri against a whitelist. Do not accept wildcard or open redirect patterns.",
                        cwe="CWE-601",
                    ))
        return results
