import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['{"$ne": ""}', '{"$gt": ""}', '{"$regex": ".*"}', '{"$ne": null}', '{"$where": "1==1"}']
ERROR_PATTERNS = [('MongoError|MongoDBError|CastError', 'NoSQL injection error')]


class ActiveNosqlInjectionCheck(BaseCheck):
    name = "active_nosql_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload in PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        for pattern, desc in ERROR_PATTERNS:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="critical",
                                    title="NoSQL Injection Detected",
                                    description="Parameter may be vulnerable to NoSQL injection via MongoDB operators ($ne, $gt, $regex).",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Validate and sanitize input. Avoid using user input directly in MongoDB queries. Use parameterised queries.",
                                    cwe="CWE-943",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="critical",
                            title="NoSQL Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Validate and sanitize input. Avoid using user input directly in MongoDB queries. Use parameterised queries.",
                            cwe="CWE-943",
                        ))
                    except Exception:
                        continue

        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import copy
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
