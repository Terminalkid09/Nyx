import re
from modules.scanner.base_check import BaseCheck, CheckResult


class AlapcaCheck(BaseCheck):
    name = "alapca"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        headers = event.get("headers", {}) or {}
        headers_lower = {k.lower(): str(v) for k, v in headers.items()}

        alpn_header = headers_lower.get("alpn", "") or headers_lower.get("x-alpn", "")
        tls_version = event.get("tls_version", "") or ""

        if alpn_header and "http/1.1" in alpn_header.lower() and "h2" not in alpn_header.lower():
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="ALPACA TLS/ALPN confusion possible",
                description=f"ALPN header indicates HTTP/1.1 only ({alpn_header}). TLS ALPN confusion attacks may be possible if the server also supports HTTPS on other ports.",
                evidence=f"ALPN: {alpn_header}\nTLS version: {tls_version}",
                remediation="Ensure consistent ALPN configuration across all TLS services. Use distinct certificates for different services on the same host.",
                cwe="CWE-295",
            ))

        if tls_version and tls_version < "1.2":
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title="Weak TLS version detected",
                description=f"TLS version {tls_version} is outdated and may be vulnerable to downgrade attacks.",
                evidence=f"TLS version: {tls_version}",
                remediation="Upgrade to TLS 1.2 or higher. Disable TLS 1.0 and TLS 1.1.",
                cwe="CWE-326",
            ))
        return results
