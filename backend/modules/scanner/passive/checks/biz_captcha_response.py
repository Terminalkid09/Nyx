import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizCaptchaResponseCheck(BaseCheck):
    name = "biz_captcha_response"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("response_body", "") or event.get("body", "") or ""
        if not body:
            return results
        captcha_patterns = [
            (r'"success"\s*:\s*true', "CAPTCHA success response"),
            (r'"score"\s*:\s*[0-9.]+', "CAPTCHA score response"),
            (r'"challenge_ts"', "CAPTCHA challenge timestamp"),
            (r'"hostname"', "CAPTCHA hostname in response"),
            (r'"error-codes"\s*:\s*\[\]', "CAPTCHA empty error codes"),
        ]
        for pattern, desc in captcha_patterns:
            if re.search(pattern, body):
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="CAPTCHA bypass via response reuse",
                    description=f"{desc}. If the application trusts client-side CAPTCHA verification responses, attackers can reuse valid responses.",
                    evidence=f"Pattern: {pattern}\nBody: {body[:300]}",
                    remediation="Verify CAPTCHA tokens server-side with the provider's API. Never trust client-side verification responses.",
                    cwe="CWE-693",
                ))
                break
        return results
