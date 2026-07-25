import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtJkuBypassCheck(BaseCheck):
    name = "jwt_jku_bypass"

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
                jku = header.get("jku", "")
                if jku:
                    if "evil" in jku.lower() or "attacker" in jku.lower() or jku.startswith("http://"):
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="JWT jku header verification bypass",
                            description=f"JWT 'jku' (JWK Set URL) points to potentially untrusted URL: '{jku}'.",
                            evidence=f"jku: {jku}\nHeader: {header}",
                            remediation="Validate the JKU URL against a whitelist of trusted JWKS endpoints.",
                            cwe="CWE-347",
                        ))
                        break
            except Exception:
                continue
        return results
