import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtExpiredTokenCheck(BaseCheck):
    name = "jwt_expired_token"

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
        import time
        for token in tokens:
            try:
                payload_b64 = token.split(".")[1]
                padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                payload = json.loads(decoded)
                exp = payload.get("exp", 0)
                if exp and exp < time.time():
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="JWT expired token accepted",
                        description="The application accepted or transmitted an expired JWT token. Expired tokens should be rejected.",
                        evidence=f"Expiration: {exp}\nCurrent time: {time.time()}\nPayload: {payload}",
                        remediation="Validate the 'exp' claim and reject expired tokens. Ensure clock skew tolerance is minimal.",
                        cwe="CWE-613",
                    ))
                    break
            except Exception:
                continue
        return results
