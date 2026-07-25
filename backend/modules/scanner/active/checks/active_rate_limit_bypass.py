import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveRateLimitBypassCheck(BaseCheck):
    name = "active_rate_limit_bypass"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            base_headers = req.get("headers", {})
            # Try multiple requests with different X-Forwarded-For values
            statuses = set()
            for i in range(5):
                try:
                    test_headers = dict(base_headers)
                    test_headers["X-Forwarded-For"] = f"192.168.1.{i}"
                    resp = await client.get(url, headers=test_headers)
                    statuses.add(resp.status_code)
                except Exception:
                    continue
            if len(statuses) < 2:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="Potential Rate Limiting Bypass via X-Forwarded-For",
                    description="The application returned the same status code across multiple IPs, suggesting IP-based rate limiting may be bypassable.",
                    evidence=f"Statuses seen: {statuses}",
                    remediation="Use real IP detection behind proxies. Implement rate limiting based on session tokens or API keys in addition to IP.",
                    cwe="CWE-770",
                ))
        return results
