import json
import base64
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtNoneAlgCheck(BaseCheck):
    name = "jwt_none_alg"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""

        for match in self._find_jwts(body):
            try:
                header_b64 = match.split(".")[0]
                padded = header_b64 + "=" * (4 - len(header_b64) % 4)
                header = json.loads(base64.urlsafe_b64decode(padded))
                alg = header.get("alg", "").lower()
                if alg == "none":
                    results.append(CheckResult(
                        triggered=True,
                        severity="critical",
                        title="JWT with 'alg: none' detected",
                        description="The server accepted a JWT with algorithm 'none', meaning no signature verification.",
                        evidence=f"JWT header: {json.dumps(header)}",
                        remediation="Configure the server to reject tokens with alg: none. Always verify the signature.",
                        cwe="CWE-347",
                    ))
            except Exception:
                continue

        return results

    def _find_jwts(self, text: str) -> list[str]:
        jwts = []
        for word in text.split():
            word = word.strip('",\'.;:')
            parts = word.split(".")
            if len(parts) == 3:
                try:
                    padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    base64.urlsafe_b64decode(padded)
                    jwts.append(word)
                except Exception:
                    continue
        return jwts
