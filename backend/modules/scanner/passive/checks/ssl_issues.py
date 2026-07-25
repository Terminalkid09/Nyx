from modules.scanner.base_check import BaseCheck, CheckResult


class SslIssuesCheck(BaseCheck):
    name = "ssl_issues"

    async def run(self, event: dict, request_data: dict) -> list[CheckResult]:
        results = []
        tls_version = event.get("tls_version")

        if tls_version in ("TLSv1.0", "TLSv1.1"):
            results.append(CheckResult(
                triggered=True,
                severity="medium",
                title=f"Outdated TLS version: {tls_version}",
                description=f"TLS {tls_version} is deprecated and vulnerable to attacks.",
                evidence=f"TLS version: {tls_version}",
                remediation="Disable TLS 1.0 and 1.1. Enable TLS 1.2 and 1.3.",
                cwe="CWE-326",
            ))

        weak_ciphers = [
            "RC4", "DES", "3DES", "EXPORT", "NULL", "MD5",
        ]
        tls_cipher = event.get("tls_cipher", "") or ""
        for weak in weak_ciphers:
            if weak.upper() in tls_cipher.upper():
                results.append(CheckResult(
                    triggered=True,
                    severity="high",
                    title=f"Weak TLS cipher: {tls_cipher}",
                    description=f"The connection uses the weak cipher {tls_cipher}.",
                    evidence=f"Cipher: {tls_cipher}",
                    remediation="Disable weak ciphers on the server. Use modern AEAD ciphers like TLS_AES_128_GCM_SHA256.",
                    cwe="CWE-327",
                ))
                break

        return results
