from modules.scanner.base_check import BaseCheck, CheckResult

DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS"]


class HttpMethodsCheck(BaseCheck):
    name = "http_methods"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        method = request_data.get("method", event.get("method", "")).upper()
        status = event.get("status")
        path = request_data.get("path", request_data.get("url", ""))

        if method not in DANGEROUS_METHODS:
            return results

        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        auth_headers = ["authorization", "x-api-key", "api-key", "x-auth-token", "token", "cookie"]
        has_auth = any(h in headers_lower for h in auth_headers)

        if not has_auth:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title=f"Dangerous HTTP method allowed without apparent authorization: {method}",
                description=f"The {method} method was accepted at {path} without visible authorization headers.",
                evidence=f"Method: {method}\nURL: {path}\nStatus: {status}",
                remediation=f"Restrict {method} requests to authenticated and authorized users only.",
                cwe="CWE-749",
            ))
        else:
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title=f"Dangerous HTTP method used: {method}",
                description=f"The {method} method was used on {path}. Verify this is intentional and properly authorized.",
                evidence=f"Method: {method}\nURL: {path}\nStatus: {status}",
                remediation=f"Ensure {method} is only exposed on endpoints that require modification, and enforce authorization.",
                cwe="CWE-749",
            ))

        if method == "TRACE":
            allow = headers_lower.get("allow", "")
            if "TRACE" in allow or status == 200:
                results.append(CheckResult(
                    triggered=True,
                    severity="medium",
                    title="TRACE method enabled (Cross-Site Tracing)",
                    description="TRACE method is enabled, potentially allowing Cross-Site Tracing (XST) attacks.",
                    evidence=f"Method: TRACE\nStatus: {status}",
                    remediation="Disable the TRACE method on the web server.",
                    cwe="CWE-603",
                ))

        return results
