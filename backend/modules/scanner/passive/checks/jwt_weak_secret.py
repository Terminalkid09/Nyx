import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtWeakSecretCheck(BaseCheck):
    name = "jwt_weak_secret"

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
        common_secrets = ["secret", "password", "123456", "admin", "key", "token", "changeme", "default", "jwt_secret", "mysecret", "pass", "access", "secretkey", "privatekey", "secret123", "test", "development", "staging", "qwerty", "abc123"]
        for token in tokens:
            try:
                import hmac
                import hashlib
                parts = token.split(".")
                message = f"{parts[0]}.{parts[1]}".encode()
                for secret in common_secrets:
                    expected_sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), message, hashlib.sha256).digest()).rstrip(b"=").decode()
                    if expected_sig == parts[2]:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="JWT weak HMAC secret",
                            description=f"JWT token signed with a weak/common secret: '{secret}'. The token can be forged easily.",
                            evidence=f"Weak secret: {secret}\nToken: {token[:80]}...",
                            remediation="Use a strong, randomly generated secret for JWT signing. Rotate secrets regularly. Use RS256 instead of HS256.",
                            cwe="CWE-347",
                        ))
                        return results
            except Exception:
                continue
        return results
