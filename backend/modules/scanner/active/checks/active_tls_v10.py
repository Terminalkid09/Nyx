from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveTlsV10Check(BaseCheck):
    name = "active_tls_v10"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results = []
        parsed = urlparse(base_request.get("url", ""))
        if parsed.scheme != "https":
            return results
        import ssl
        import socket
        try:
            hostname = parsed.netloc.split(":")[0]
            port = 443
            if ":" in parsed.netloc:
                port = int(parsed.netloc.split(":")[1])
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    if version and "TLSv1.0" in version:
                        results.append(CheckResult(
                            triggered=True,
                            severity="medium",
                            title="TLSv1.0 Support Detected",
                            description="Server supports TLSv1.0 protocol which is deprecated and vulnerable to multiple attacks including BEAST and POODLE.",
                            evidence=f"Negotiated version: {version}",
                            remediation="Disable deprecated protocols. Support only TLSv1.2 and TLSv1.3.",
                            cwe="CWE-326",
                        ))
        except Exception:
            pass
        return results
