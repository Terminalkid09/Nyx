import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizQuantityCheck(BaseCheck):
    name = "biz_quantity"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("request_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        quantity_params = ["quantity", "qty", "count", "amount", "items"]
        for param in quantity_params:
            pattern = rf"[?&]{param}=(\d+)"
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                value = int(match.group(1))
                if value < 0 or value > 999:
                    results.append(CheckResult(
                        triggered=True,
                        severity="medium",
                        title="Quantity manipulation",
                        description=f"Quantity parameter '{param}={value}' detected. Negative or excessive quantities indicate business logic tampering.",
                        evidence=f"Parameter: {param}={value}\nURL: {url}",
                        remediation="Validate quantity values server-side. Reject negative and unreasonably large quantities.",
                        cwe="CWE-472",
                    ))
                    break
        return results
