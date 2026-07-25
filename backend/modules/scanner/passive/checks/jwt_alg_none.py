import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtAlgNoneCheck(BaseCheck):
    name = "jwt_alg_none"

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
                if header.get("alg", "").lower() == "none":
                    results.append(CheckResult(
                        triggered=True,
                        severity="critical",
                        title="JWT alg=none in header",
                        description="JWT token has 'alg': 'none' in its header, which would allow signature verification bypass if the server implements it.",
                        evidence=f"Token header: {header}\nToken: {token[:80]}...",
                        remediation="Reject tokens with 'alg': 'none'. Enforce a whitelist of accepted algorithms (e.g., HS256, RS256).",
                        cwe="CWE-347",
                    ))
                    break
            except Exception:
                continue
        return results
