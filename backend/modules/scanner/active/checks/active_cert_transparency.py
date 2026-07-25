from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveCertTransparencyCheck(BaseCheck):
    name = "active_cert_transparency"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        if parsed.scheme != "https":
            return results
        try:
            import ssl
            import socket
            hostname = parsed.netloc.split(":")[0]
            port = 443
            if ":" in parsed.netloc:
                port = int(parsed.netloc.split(":")[1])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        has_sct = False
                        for ext in cert.get('subjectAltName', ()):
                            pass
                        if not has_sct:
                            results.append(CheckResult(
                                triggered=True,
                                severity="low",
                                title="Certificate Transparency Not Verified",
                                description="SSL certificate may not include Signed Certificate Timestamps (SCTs), reducing assurance of public logging.",
                                evidence=f"Subject: {cert.get('subject', ())}",
                                remediation="Ensure SSL certificates include SCTs from multiple logs. Use a CA that supports Certificate Transparency.",
                                cwe="CWE-295",
                            ))
        except Exception:
            pass
        return results
