import re
from modules.scanner.base_check import BaseCheck, CheckResult


class RaceCouponCheck(BaseCheck):
    name = "race_coupon"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        coupon_keywords = ["coupon", "promo", "discount", "voucher", "gift", "code", "redeem"]
        is_coupon = any(k in path.lower() for k in coupon_keywords)
        if is_coupon:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Race condition in coupon usage",
                description=f"Coupon/promo endpoint at '{path}'. Race conditions can allow single-use coupon codes to be used multiple times.",
                evidence=f"Path: {path}",
                remediation="Use atomic database operations with constraints. Implement idempotency and check coupon usage within a transaction.",
                cwe="CWE-362",
            ))
        return results
