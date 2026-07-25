import re
from modules.scanner.base_check import BaseCheck, CheckResult


class BizCaptchaDirectCheck(BaseCheck):
    name = "biz_captcha_direct"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        path = request_data.get("path", request_data.get("url", ""))
        body = event.get("request_body", "") or event.get("body", "") or ""
        combined = path + " " + body
        captcha_endpoints = re.findall(r"(captcha|recaptcha|g-recaptcha|hcaptcha|turnstile)", combined, re.IGNORECASE)
        if captcha_endpoints:
            referer = (request_data.get("headers", {}) or {}).get("referer", request_data.get("headers", {}) or {}).get("Referer", "")
            if not referer:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="CAPTCHA bypass via direct request",
                    description=f"CAPTCHA verification endpoint accessed without a Referer header. Direct requests may bypass client-side validation.",
                    evidence=f"Path: {path}\nBody: {body[:200]}",
                    remediation="Validate Referer/origin headers on CAPTCHA verification endpoints. Require CSRF tokens for state-changing requests.",
                    cwe="CWE-693",
                ))
        return results
