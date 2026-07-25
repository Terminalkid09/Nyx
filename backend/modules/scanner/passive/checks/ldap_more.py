import re
from modules.scanner.base_check import BaseCheck, CheckResult


class LdapMoreCheck(BaseCheck):
    name = "ldap_more"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = event.get("url", "") or request_data.get("url", "")
        body = event.get("request_body", "") or ""
        response_body = event.get("response_body", "") or ""
        combined = f"{url} {body} {response_body}"

        ldap_patterns = [
            (r"\*\)\(\(&", "LDAP injection: *)((& pattern"),
            (r"\|\(uid=\*\)", "LDAP injection: |(uid=*) pattern"),
            (r"\)\s*\(&\s*\(", "LDAP injection: )(&( pattern"),
            (r"admin\*\)", "LDAP injection: admin*) pattern"),
            (r"\*\)\(\(&\(cm=", "LDAP injection: *)((&(cm= pattern"),
            (r"\|\(uid=\*\)", "LDAP injection: |(uid=*) pattern"),
            (r"\(\)\(\(\)", "LDAP injection: empty filter"),
        ]
        for pattern, desc in ldap_patterns:
            if re.search(pattern, combined):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="LDAP injection variant detected",
                    description=f"{desc} found. LDAP injection may allow bypassing authentication or data exfiltration.",
                    evidence=f"Pattern: {pattern}\nRequest: {combined[:500]}",
                    remediation="Escape LDAP special characters. Use parameterised LDAP queries. Validate and sanitize all user input.",
                    cwe="CWE-90",
                ))
                break
        return results
