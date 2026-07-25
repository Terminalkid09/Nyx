import re
from modules.scanner.base_check import BaseCheck, CheckResult


class JwtExposureCheck(BaseCheck):
    name = "jwt_exposure"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        body = event.get("body", "") or ""
        headers = event.get("headers", {}) or {}
        url = request_data.get("url", "")
        referrer = request_data.get("referrer", headers.get("referer", headers.get("Referer", "")))

        jwt_pattern = re.compile(
            r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'
        )

        jwt_in_url = jwt_pattern.findall(url)
        for token in jwt_in_url:
            results.append(CheckResult(
                triggered=True,
                severity="critical",
                title="JWT exposed in URL",
                description="A JSON Web Token was found in the URL query parameters or path, which can be logged or leaked via Referer header.",
                evidence=f"Token found in URL: {token[:80]}...",
                remediation="Transmit JWTs in Authorization headers, not in URL query strings.",
                cwe="CWE-598",
            ))

        if referrer:
            jwt_in_referrer = jwt_pattern.findall(referrer)
            for token in jwt_in_referrer:
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title="JWT leaked via Referer header",
                    description="A JWT was found in the Referer header, indicating potential leakage to third-party origins.",
                    evidence=f"Referrer: {referrer[:200]}",
                    remediation="Use Referrer-Policy: no-referrer or same-origin. Avoid placing tokens in URLs.",
                    cwe="CWE-200",
                ))

        jwt_in_body = jwt_pattern.findall(body)
        for token in jwt_in_body:
            results.append(CheckResult(
                triggered=True,
                severity="high",
                title="JWT found in response body",
                description="A JWT was found in the response body, possibly exposing tokens in non-standard locations.",
                evidence=f"Token: {token[:80]}...",
                remediation="Ensure JWTs are only sent in HTTP-only cookies or Authorization headers, not in response bodies.",
                cwe="CWE-200",
            ))

        auth_header = headers.get("authorization", headers.get("Authorization", ""))
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
            if jwt_pattern.match(token):
                results.append(CheckResult(
                    triggered=True,
                    severity="info",
                    title="JWT used in Authorization header",
                    description="JWT is transmitted in the standard Authorization header, which is good practice.",
                    evidence="JWT in Authorization header",
                    remediation="No change needed. This is an informational finding.",
                    cwe="CWE-200",
                ))

        return results
