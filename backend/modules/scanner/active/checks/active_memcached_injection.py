import re
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


PAYLOADS = ['%0d%0Aset injected_key 0 0 5%0d%0avalue', '%0aget injected_key', '\r\nget injected_key']
ERROR_PATTERNS = [('ERROR|STORED|END|memcached error', 'Memcached injection response')]


class ActiveMemcachedInjectionCheck(BaseCheck):
    name = "active_memcached_injection"

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
                                    severity="high",
                                    title="Memcached Command Injection Detected",
                                    description="Parameter may be vulnerable to Memcached command injection via CRLF. Memcached commands sent as input may have been processed.",
                                    evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                    remediation="Validate and sanitize all input. Avoid constructing Memcached commands from user input. Use input filtering.",
                                    cwe="CWE-93",
                                ))
                                break
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Memcached Command Injection Detected (Timeout)",
                            description="Request timed out with payload.",
                            evidence=f"Payload: {payload}",
                            remediation="Validate and sanitize all input. Avoid constructing Memcached commands from user input. Use input filtering.",
                            cwe="CWE-93",
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
