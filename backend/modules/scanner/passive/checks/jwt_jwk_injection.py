import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtJwkInjectionCheck(BaseCheck):
    name = "jwt_jwk_injection"

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
                jwk = header.get("jwk", None)
                if jwk and isinstance(jwk, dict):
                    results.append(CheckResult(
                        triggered=True,
                        severity="critical",
                        title="JWT jwk header injection",
                        description="JWT token contains an embedded JWK (JSON Web Key) in the header, allowing the client to provide its own public key.",
                        evidence=f"Header: {header}",
                        remediation="Do not accept embedded JWK keys. Use a whitelist of trusted JWKS endpoints instead.",
                        cwe="CWE-347",
                    ))
                    break
            except Exception:
                continue
        return results
