import re
from modules.scanner.base_check import BaseCheck, CheckResult


class CorsMaxAgeLongCheck(BaseCheck):
    name = "cors_max_age_long"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        max_age = headers_lower.get("access-control-max-age", "")
        if max_age:
            try:
                seconds = int(str(max_age).strip())
                if seconds > 3600:
                    results.append(CheckResult(
                        triggered=True,
                        severity="low",
                        title="Overly Long CORS Preflight Cache Duration",
                        description="Access-Control-Max-Age is set to a very long duration (over 1 hour). Long preflight caching reduces flexibility for CORS policy changes.",
                        evidence=f"Access-Control-Max-Age: {seconds} seconds",
                        remediation="Set Access-Control-Max-Age to a reasonable duration (e.g., 600 seconds or less) to allow timely propagation of policy changes.",
                        cwe="CWE-942",
                    ))
            except ValueError:
                pass

        return results
