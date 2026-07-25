from modules.scanner.base_check import BaseCheck, CheckResult


class RateLimitingCheck(BaseCheck):
    name = "rate_limiting"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}
        status = event.get("status")

        if status == 429:
            retry_after = headers_lower.get("retry-after", headers_lower.get("retry-after", ""))
            results.append(CheckResult(
                triggered=True,
                severity="info",
                title="Rate limit triggered (429 Too Many Requests)",
                description="The application returned a 429 status code, indicating rate limiting is in place.",
                evidence=f"Status: 429\nRetry-After: {retry_after}",
                remediation="Rate limiting is active. Ensure limits are reasonable and return meaningful Retry-After headers.",
                cwe="CWE-770",
            ))

        rate_limit_headers = []
        for hdr, val in headers_lower.items():
            if hdr.startswith("x-ratelimit"):
                rate_limit_headers.append(f"{hdr}: {val}")

        if rate_limit_headers:
            results.append(CheckResult(
                triggered=True,
                severity="info",
                title="Rate limiting headers detected",
                description="Response includes rate limiting headers, indicating active rate limiting.",
                evidence="\n".join(rate_limit_headers),
                remediation="Rate limiting is active. This is an informational finding.",
                cwe="CWE-770",
            ))

        retry_after = headers_lower.get("retry-after", "")
        if retry_after and status != 429:
            results.append(CheckResult(
                triggered=True,
                severity="low",
                title="Retry-After header present",
                description=f"Response includes Retry-After: {retry_after} without a 429 status, which may indicate rate limiting at a proxy/CDN level.",
                evidence=f"Retry-After: {retry_after}\nStatus: {status}",
                remediation="Ensure Retry-After is only used with appropriate status codes (429, 503).",
                cwe="CWE-770",
            ))

        return results
