import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


CMD_PAYLOADS = [
    ("; sleep 5", "sleep"),
    ("| sleep 5", "sleep"),
    ("& sleep 5&", "sleep"),
    ("&& sleep 5&&", "sleep"),
    ("`sleep 5`", "sleep"),
    ("$(sleep 5)", "sleep"),
    ("; ping -c 5 127.0.0.1", "ping"),
    ("| ping -n 5 127.0.0.1", "ping"),
    ("& ping -n 5 127.0.0.1&", "ping"),
    ("; timeout 5", "timeout"),
    ("| timeout 5", "timeout"),
    ("& timeout 5&", "timeout"),
]


class CmdInjectionVariantsCheck(BaseCheck):
    name = "active_cmd_injection_variants"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for param in target_params:
                for payload, _ in CMD_PAYLOADS:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified, timeout=5)
                    except httpx.TimeoutException:
                        results.append(CheckResult(
                            triggered=True,
                            severity="high",
                            title="Possible blind command injection",
                            description=f"Parameter '{param}' caused a timeout with payload: {payload}",
                            evidence=f"Payload: {payload}",
                            remediation="Avoid shell execution with user input. Use safe APIs.",
                            cwe="CWE-78",
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
        if param in params:
            params[param] = payload
            req["url"] = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
        return req
