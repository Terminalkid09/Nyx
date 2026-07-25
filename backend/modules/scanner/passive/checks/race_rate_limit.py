import re
from modules.scanner.base_check import BaseCheck, CheckResult


class RaceRateLimitCheck(BaseCheck):
    name = "race_rate_limit"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        status = event.get("status")
        rate_limit_headers = [h for h in headers_lower if "ratelimit" in h or "rate-limit" in h]
        if rate_limit_headers and status == 200:
            remaining = ""
            for h in headers_lower:
                if "remaining" in h or "ratelimit" in h:
                    val = headers_lower[h]
                    if val.isdigit() and int(val) <= 2:
                        remaining = f"{h}: {val}"
            if remaining:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Race condition in rate limiting",
                    description="Rate limit is nearly exhausted. Concurrent requests may bypass rate limiting due to race conditions in rate limit counters.",
                    evidence=f"{remaining}\nRate limit headers: {rate_limit_headers}",
                    remediation="Use atomic operations for rate limit counters. Consider using a sliding window algorithm with proper locking.",
                    cwe="CWE-362",
                ))
        return results
