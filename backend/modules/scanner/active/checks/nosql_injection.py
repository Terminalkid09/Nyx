import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


NOSQL_PAYLOADS = [
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$ne": null}',
    '{"$gt": null}',
    '{"$in": ["admin", "root"]}',
    '{"$or": [{"$ne": ""}, {"$ne": ""}]}',
]


class NosqlInjectionCheck(BaseCheck):
    name = "active_nosql_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            for param in target_params:
                for payload in NOSQL_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="NoSQL injection detected",
                                description=f"Parameter '{param}' may be vulnerable to NoSQL injection.",
                                evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                remediation="Validate and sanitize all user input. Use strict schema validation.",
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
