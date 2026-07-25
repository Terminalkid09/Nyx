import base64
import copy
import json
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtNoneActiveCheck(BaseCheck):
    name = "jwt_none_active"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        headers = base_request.get("headers", {}) or {}
        auth_header = headers.get("authorization", headers.get("Authorization", ""))
        if not auth_header.lower().startswith("bearer "):
            return results

        original_token = auth_header[7:].strip()
        parts = original_token.split(".")
        if len(parts) != 3:
            return results

        none_payloads = [
            {"alg": "none", "typ": "JWT"},
            {"alg": "None", "typ": "JWT"},
            {"alg": "NONE", "typ": "JWT"},
            {"alg": "none", "typ": "JWT", "kid": "none"},
            {"alg": "none"},
        ]

        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for header_dict in none_payloads:
                encoded_header = base64.urlsafe_b64encode(
                    json.dumps(header_dict).encode()
                ).rstrip(b"=").decode()

                payload_b64 = parts[1]
                modified_token = f"{encoded_header}.{payload_b64}."

                modified = copy.deepcopy(base_request)
                mod_headers = dict(modified.get("headers", {}))
                mod_headers["Authorization"] = f"Bearer {modified_token}"
                modified["headers"] = mod_headers

                try:
                    resp = await client.request(**modified)
                    if resp.status_code not in (401, 403):
                        status_diff = resp.status_code not in (400, 500)
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="JWT 'none' algorithm attack possible",
                            description="Server accepted a JWT with 'alg: none', allowing token forgery.",
                            evidence=f"Algorithm: {header_dict['alg']}\n"
                                     f"Original token: {original_token[:50]}...\n"
                                     f"Response status: {resp.status_code}",
                            remediation="Reject tokens with 'alg: none'. Configure the JWT library to enforce a "
                                        "whitelist of accepted algorithms.",
                            cwe="CWE-347",
                        ))
                except Exception:
                    continue

        return results
