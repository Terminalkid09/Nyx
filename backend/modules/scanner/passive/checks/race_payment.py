import re
from modules.scanner.base_check import BaseCheck, CheckResult


class RacePaymentCheck(BaseCheck):
    name = "race_payment"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        path = request_data.get("path", "") or ""
        payment_keywords = ["payment", "checkout", "purchase", "buy", "order", "charge", "invoice", "pay", "transaction"]
        is_payment = any(k in path.lower() or k in url.lower() for k in payment_keywords)
        if not is_payment:
            return results
        results.append(CheckResult(
            triggered=True,
            severity="high",
            title="Race condition in payment endpoint",
            description=f"Payment-related endpoint at '{path}'. Race conditions in payment processing can lead to balance manipulation or duplicate charges.",
            evidence=f"URL: {url}\nPath: {path}",
            remediation="Use idempotency keys for payment operations. Implement pessimistic locking. Verify balance before and after transactions.",
            cwe="CWE-362",
        ))
        return results
