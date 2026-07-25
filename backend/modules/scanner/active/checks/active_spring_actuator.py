import re
import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult

PATHS = ['/actuator', '/actuator/health', '/actuator/info', '/actuator/env', '/actuator/heapdump', '/actuator/threaddump', '/actuator/metrics', '/actuator/beans', '/actuator/mappings', '/heapdump']
SUCCESS_INDICATORS = ['"status"', '"health"', '"diskSpace"', '"spring"', '"application"']


class ActiveSpringActuatorCheck(BaseCheck):
    name = "active_spring_actuator"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            for path in PATHS:
                try:
                    req = dict(base_request)
                    parsed = urlparse(req.get("url", ""))
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
                    resp = await client.get(f"{base_url}{path}", headers=req.get("headers", {}))
                    for indicator in SUCCESS_INDICATORS:
                        if indicator in resp.text and resp.status_code == 200:
                            results.append(CheckResult(
                                triggered=True,
                                severity="high",
                                title="Spring Boot Actuator Exposed",
                                description="Spring Boot Actuator endpoints are exposed without authentication, revealing application internals, heap dumps, and environment variables.",
                                evidence=f"Path: {path} - found {indicator}",
                                remediation="Secure Spring Boot Actuator endpoints. Set management.endpoints.web.exposure.include to minimal set. Add authentication. Use separate management port.",
                                cwe="CWE-200",
                            ))
                            break
                except Exception:
                    continue
        return results
