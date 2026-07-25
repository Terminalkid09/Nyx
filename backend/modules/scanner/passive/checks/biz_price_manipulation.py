import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizPriceManipulationCheck(BaseCheck):
    name = "biz_price_manipulation"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("request_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        price_params = ["price", "amount", "cost", "total", "value", "charge", "fee", "subtotal", "discount"]
        for param in price_params:
            pattern = rf"[?&]{param}=(-?\d+\.?\d*)"
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                value = float(match.group(1))
                if value <= 0 or value > 1000000:
                    results.append(CheckResult(
                        triggered=True,
                        severity="high",
                        title="Price manipulation via parameter tampering",
                        description=f"Price parameter '{param}={value}' detected. Unusual price values may indicate parameter tampering attempts.",
                        evidence=f"Parameter: {param}={value}\nURL: {url}",
                        remediation="Never trust client-side price values. Always calculate prices server-side from the database. Validate price ranges strictly.",
                        cwe="CWE-472",
                    ))
                    break
        return results
