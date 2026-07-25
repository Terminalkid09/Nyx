import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizNegativeValueCheck(BaseCheck):
    name = "biz_negative_value"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("request_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        numeric_params = re.finditer(r"[?&](\w+)=(-?\d+\.?\d*)", combined)
        for match in numeric_params:
            param = match.group(1)
            value = float(match.group(2))
            if value < 0 and param.lower() not in ["temperature", "offset"]:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="Negative value injection",
                    description=f"Parameter '{param}' has a negative value '{value}'. Negative values in financial or quantity fields can lead to balance manipulation.",
                    evidence=f"Parameter: {param}={value}\nURL: {url}",
                    remediation="Validate that numeric parameters must be positive. Reject negative values for financial and quantity fields.",
                    cwe="CWE-472",
                ))
                break
        return results
