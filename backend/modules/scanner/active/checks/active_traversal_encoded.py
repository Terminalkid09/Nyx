import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode


ENCODED_TRAVERSAL_PAYLOADS = [
    ("URL encoded", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("Double URL encoded", "%252e%252e%252fetc%252fpasswd"),
    ("Unicode encoded", "..%252f..%252f..%252fetc/passwd"),
    ("UTF-8 encoded", "..%c0%af..%c0%afetc%c0%afpasswd"),
    ("16-bit Unicode", "..%uff0e%uff0e/etc/passwd"),
    ("Hex encoded", "..\\x2e\\x2e\\x2fetc\\x2fpasswd"),
]


class ActiveTraversalEncodedCheck(BaseCheck):
    name = "active_traversal_encoded"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for encoding_name, payload in ENCODED_TRAVERSAL_PAYLOADS:
                    modified = dict(base_request)
                    parsed = urlparse(modified["url"])
                    params = dict(parse_qsl(parsed.query))
                    params[param] = payload
                    modified["url"] = parsed._replace(query=urlencode(params)).geturl()
                    try:
                        resp = await client.request(**modified)
                        if "root:x:0:0:" in resp.text or "root:" in resp.text[:2000]:
                            results.append(CheckResult(
                                triggered=True,
                                severity="critical",
                                title=f"Encoded Path Traversal ({encoding_name})",
                                description=f"Parameter '{param}' vulnerable to encoded path traversal.",
                                evidence=f"Encoding: {encoding_name}\nPayload: {payload}",
                                remediation="Normalize and validate paths. Reject encoded traversal sequences. Use a mapping for file access.",
                                cwe="CWE-22",
                            ))
                    except Exception:
                        continue
        return results
