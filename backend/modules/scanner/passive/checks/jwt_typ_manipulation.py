import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtTypManipulationCheck(BaseCheck):
    name = "jwt_typ_manipulation"

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
                typ = header.get("typ", "")
                if typ and typ.upper() != "JWT":
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="JWT typ header manipulation",
                        description=f"JWT 'typ' header is set to '{typ}' instead of 'JWT', which may indicate an attempt to bypass security controls.",
                        evidence=f"typ: {typ}\nHeader: {header}",
                        remediation="Validate the 'typ' header and reject tokens with unexpected type values.",
                        cwe="CWE-347",
                    ))
                    break
            except Exception:
                continue
        return results
