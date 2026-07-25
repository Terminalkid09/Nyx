import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtCritBypassCheck(BaseCheck):
    name = "jwt_crit_bypass"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        auth = headers.get("authorization", headers.get("Authorization", ""))
        tokens = []
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        if auth.lower().startswith("bearer "):
            token = auth[7:]
            tokens.append(token)
        tokens += jwt_pattern.findall(body)
        import base64
        import json
        for token in tokens:
            try:
                header_b64 = token.split(".")[0]
                padded = header_b64 + "=" * (4 - len(header_b64) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                header = json.loads(decoded)
                crit = header.get("crit", [])
                if crit and isinstance(crit, list):
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="JWT crit header bypass",
                        description=f"JWT header contains 'crit' (critical) extension list: {crit}. Some implementations mishandle critical headers.",
                        evidence=f"crit: {crit}\nHeader: {header}",
                        remediation="Ensure the JWT library properly validates critical headers. Critical headers should be understood by the server.",
                        cwe="CWE-347",
                    ))
                    break
            except Exception:
                continue
        return results
