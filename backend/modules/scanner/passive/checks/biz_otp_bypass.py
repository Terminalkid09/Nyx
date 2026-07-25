import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizOtpBypassCheck(BaseCheck):
    name = "biz_otp_bypass"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        otp_response_patterns = [
            (r'"verified"\s*:\s*true', "OTP verification success response"),
            (r'"status"\s*:\s*"verified"', "OTP status verified"),
            (r'"otp"\s*:\s*"\d{4,8}"', "OTP value in response body"),
            (r'"code"\s*:\s*"\d{4,8}"', "OTP code in response body"),
            (r'"2fa"\s*:\s*(true|false)', "2FA status in response body"),
        ]
        for pattern, desc in otp_response_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="OTP bypass via response manipulation",
                    description=f"{desc}. If OTP verification relies on client-side response status, attackers can manipulate the response to bypass OTP.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:300]}",
                    remediation="Verify OTP tokens server-side. Never return OTP/verification status in responses that clients can parse.",
                    cwe="CWE-287",
                ))
                break
        return results
