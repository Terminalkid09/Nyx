import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizIntegerOverflowCheck(BaseCheck):
    name = "biz_integer_overflow"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        url = request_data.get("url", "") or event.get("url", "")
        body = event.get("request_body", "") or event.get("body", "") or ""
        combined = f"{url} {body}"
        large_numbers = re.finditer(r"[?&](\w+)=(\d{10,})", combined)
        for match in large_numbers:
            param = match.group(1)
            value = match.group(2)
            if len(value) >= 10:
                try:
                    num = int(value)
                    if num > 2147483647:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="Integer overflow in amounts",
                            description=f"Parameter '{param}' has a very large value '{value}' that may cause integer overflow in some systems.",
                            evidence=f"Parameter: {param}={value}\nURL: {url}",
                            remediation="Validate that numeric values do not exceed safe integer bounds. Use appropriate data types (BIGINT, DECIMAL) for large numbers.",
                            cwe="CWE-190",
                        ))
                        break
                except ValueError:
                    pass
        return results
