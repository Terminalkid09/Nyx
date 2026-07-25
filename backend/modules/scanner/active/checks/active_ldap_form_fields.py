import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['*)(uid=*))(|(uid=*', '*', '*)(|(uid=*']
ERROR_PATTERNS = [('LDAPException|bad search filter|Protocol error', 'LDAP injection in form fields')]


class ActiveLdapFormFieldsCheck(BaseCheck):
    name = "active_ldap_form_fields"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload in PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        for pattern, desc in ERROR_PATTERNS:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="LDAP Injection in Form Fields",
                                    description="LDAP injection payloads sent in form fields resulted in errors or unexpected behavior, indicating LDAP query manipulation.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Use LDAP escaping functions for all user input. Validate and sanitize form field values before LDAP queries.",
                                    cwe="CWE-90",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="LDAP Injection in Form Fields (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Use LDAP escaping functions for all user input. Validate and sanitize form field values before LDAP queries.",
                            cwe="CWE-90",
                        ))
                    except Exception:
                        continue

        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
