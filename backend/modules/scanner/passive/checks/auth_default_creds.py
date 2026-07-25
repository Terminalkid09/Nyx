import json
import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AuthDefaultCredsCheck(BaseCheck):
    name = "auth_default_creds"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        combined = f"{body} {json.dumps(dict(headers_lower))}" if body else json.dumps(dict(headers_lower))
        default_patterns = [
            (r"admin\s*/\s*admin", "admin/admin credentials"),
            (r"admin\s*/\s*password", "admin/password credentials"),
            (r"admin\s*/\s*12345", "admin/12345 credentials"),
            (r"root\s*/\s*root", "root/root credentials"),
            (r"root\s*/\s*admin", "root/admin credentials"),
            (r"test\s*/\s*test", "test/test credentials"),
            (r"guest\s*/\s*guest", "guest/guest credentials"),
            (r"user\s*/\s*user", "user/user credentials"),
            (r"default\s*/\s*default", "default/default credentials"),
        ]
        for pattern, desc in default_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Default credentials in response",
                    description=f"{desc} found in response. Default credentials are a common attack vector.",
                    evidence=f"Pattern: {pattern}\nSource: response body/headers",
                    remediation="Change all default credentials immediately. Enforce strong password policies for all accounts.",
                    cwe="CWE-798",
                ))
                break
        return results
