import copy
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class LdapInjectionActiveCheck(BaseCheck):
    name = "active_ldap_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = [")", "*)", "(&(1=0))", "(&(1=1))", "*)(&", "admin*", "*", "*|", "|*"]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        error_patterns = [r"bad search filter", r"ldap.*error", r"invalid dn syntax", r"protocol error", r"ldap_result", r"no such object"]
                        for pattern in error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="LDAP injection detected",
                                    description=f"Parameter '{param}' triggered an LDAP error with payload '{payload}'.",
                                    evidence=f"Payload: {payload}\nError pattern: {pattern}",
                                    remediation="Sanitize LDAP search filters. Use parameterised LDAP queries or escape special characters.",
                                    cwe="CWE-90",
                                ))
                                break
                    except Exception:
                        continue
        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
