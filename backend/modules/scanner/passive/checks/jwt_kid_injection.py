import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtKidInjectionCheck(BaseCheck):
    name = "jwt_kid_injection"

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
                kid = header.get("kid", "")
                if kid:
                    if re.search(r'\.\./', kid) or re.search(r'/etc/passwd', kid) or re.search(r'file://', kid) or re.search(r'%00', kid):
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="JWT kid injection attack",
                            description=f"JWT 'kid' header contains path traversal or injection characters: '{kid}'.",
                            evidence=f"kid: {kid}\nHeader: {header}",
                            remediation="Validate the 'kid' header strictly. Do not use user-supplied values to read files or query databases.",
                            cwe="CWE-347",
                        ))
                        break
            except Exception:
                continue
        return results
