import copy
import re
import urllib.parse
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class OAuthMisconfigCheck(BaseCheck):
    name = "oauth_misconfig"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            parsed = urllib.parse.urlparse(base_request["url"])
            qs_params = dict(urllib.parse.parse_qsl(parsed.query))

            oauth_params = ["redirect_uri", "response_type", "scope", "client_id",
                            "state", "nonce", "code", "token"]
            has_oauth = any(p in qs_params for p in oauth_params)
            if not has_oauth:
                return results

            redirect_tests = [
                ("evil.com", "https://evil.com"),
                ("evil.com/oauth", "https://evil.com/oauth"),
                ("localhost", "https://localhost"),
                ("127.0.0.1", "https://127.0.0.1"),
                ("open redirector", "https://trusted.com@evil.com"),
                ("path traversal", "https://trusted.com/../evil.com"),
                ("subdomain", "https://evil.com.trusted.com"),
                ("data URI", "data:text/html,<script>alert(1)</script>"),
                ("javascript URI", "javascript:alert(1)"),
            ]

            for test_name, test_url in redirect_tests:
                if "redirect_uri" in qs_params:
                    modified = copy.deepcopy(base_request)
                    mod_qs = dict(qs_params)
                    mod_qs["redirect_uri"] = test_url
                    modified["url"] = parsed._replace(
                        query=urllib.parse.urlencode(mod_qs)
                    ).geturl()

                    try:
                        resp = await client.request(**modified)
                        body_lower = resp.text.lower() if resp.text else ""
                        location = resp.headers.get("location", "").lower()

                        if "evil.com" in body_lower or "evil.com" in location:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title=f"OAuth redirect_uri validation bypass: {test_name}",
                                description=f"Redirect URI was modified to '{test_url}' and was accepted/reflected.",
                                evidence=f"Test: {test_name}\nRedirect URI: {test_url}\nStatus: {resp.status_code}",
                                remediation="Strictly validate the redirect_uri against a whitelist. "
                                            "Do not use string contains checks.",
                                cwe="CWE-601",
                            ))
                    except Exception:
                        continue

            response_type_tests = ["token", "code token", "id_token token", "code id_token token", "*"]
            for rtype in response_type_tests:
                if "response_type" in qs_params:
                    modified = copy.deepcopy(base_request)
                    mod_qs = dict(qs_params)
                    mod_qs["response_type"] = rtype
                    modified["url"] = parsed._replace(
                        query=urllib.parse.urlencode(mod_qs)
                    ).geturl()

                    try:
                        resp = await client.request(**modified)
                        if resp.status_code not in (400, 401, 403):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title=f"OAuth response_type manipulation: '{rtype}'",
                                description=f"Server accepted non-standard response_type '{rtype}'.",
                                evidence=f"Response type: {rtype}\nStatus: {resp.status_code}",
                                remediation="Restrict response_type to a whitelist of allowed values.",
                                cwe="CWE-287",
                            ))
                    except Exception:
                        continue

            scope_tests = ["*", "admin", "superuser", "all", "read write admin", "$ALL"]
            for scope in scope_tests:
                if "scope" in qs_params:
                    modified = copy.deepcopy(base_request)
                    mod_qs = dict(qs_params)
                    mod_qs["scope"] = scope
                    modified["url"] = parsed._replace(
                        query=urllib.parse.urlencode(mod_qs)
                    ).geturl()

                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200:
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title=f"OAuth scope escalation: '{scope}'",
                                description=f"Server accepted scope '{scope}' which may grant excessive permissions.",
                                evidence=f"Scope: {scope}\nStatus: {resp.status_code}",
                                remediation="Validate requested scopes against a whitelist. "
                                            "Restrict scope values to documented options.",
                                cwe="CWE-287",
                            ))
                    except Exception:
                        continue

        return results
