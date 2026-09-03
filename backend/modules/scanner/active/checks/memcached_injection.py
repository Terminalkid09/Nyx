import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class MemcachedInjectionCheck(BaseCheck):
    name = "active_memcached_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = ["\r\nset injected_key 0 0 5\r\nhello\r\n", "\r\nget injected_key\r\n", "\r\ndelete injected_key\r\n"]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200:
                            indicators = ["STORED", "END", "DELETED", "ERROR"]
                            for ind in indicators:
                                if ind in resp.text:
                                    results.append(CheckResult(
                                        triggered=True,
                                        severity="high",
                                        title="Memcached injection detected",
                                        description=f"Parameter '{param}' may be vulnerable to Memcached command injection.",
                                        evidence=f"Payload: {payload[:50]}...\nIndicator: {ind}",
                                        remediation="Sanitize input before using in Memcached commands. Use parameterised access patterns.",
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
        params[param] = payload
        req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
