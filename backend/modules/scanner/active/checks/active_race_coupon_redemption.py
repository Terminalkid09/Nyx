import httpx
from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveRaceCouponRedemptionCheck(BaseCheck):
    name = "active_race_coupon_redemption"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            req = dict(base_request)
            parsed = urlparse(req.get("url", ""))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            responses = []
            import asyncio
            tasks = []
            for i in range(5):
                tasks.append(client.request("POST", url, headers=req.get("headers", {})))
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for r in completed:
                if isinstance(r, Exception):
                    continue
                responses.append(r.status_code)
            if len(responses) >= 3 and len(set(responses)) == 1 and responses[0] in [200, 201, 202]:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Race Condition - Concurrent Coupon Redemption",
                    description="Concurrent coupon redemption requests may allow a single coupon to be redeemed multiple times.",
                    evidence=f"Sent 5 concurrent requests, got {len(responses)} responses with status {set(responses)}",
                    remediation="Use atomic database operations for coupon redemption. Mark coupons as used within transactions.",
                    cwe="CWE-362",
                ))
        return results
