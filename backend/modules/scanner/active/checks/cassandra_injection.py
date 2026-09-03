import copy
import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class CassandraInjectionCheck(BaseCheck):
    name = "active_cassandra_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = ["' OR '1'='1", "'; DROP TABLE system.local;--", "' ALLOW FILTERING;--"]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        error_patterns = [r"cassandra", r"cql", r"invalid query", r"syntax error", r"no viable alternative", r"cassandra.*exception"]
                        for pattern in error_patterns:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="Cassandra injection detected",
                                    description=f"Parameter '{param}' triggered a Cassandra/CQL error with payload '{payload}'.",
                                    evidence=f"Payload: {payload}\nError pattern: {pattern}",
                                    remediation="Use parameterised CQL queries (PreparedStatement). Avoid string concatenation in CQL queries.",
                                    cwe="CWE-943",
                                ))
                                break
                    except Exception:
                        continue
        return results

    def _inject_payload(self, base: dict, param: str, payload: str) -> dict:
        import urllib.parse
        req = copy.deepcopy(base)
        parsed = urllib.parse.urlparse(req["url"])
        params = dict(urllib.parse.parse_qsl(parsed.query))
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
