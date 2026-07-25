from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveOcspStaplingCheck(BaseCheck):
    name = "active_ocsp_stapling"

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
                    ocsp_resp = ssock.getpeercert(True)
                    if ocsp_resp is None:
                        results.append(CheckResult(
                            triggered=True,
                            severity="low",
                            title="OCSP Stapling Not Enabled",
                            description="Server does not send OCSP stapled responses, increasing TLS handshake latency and privacy concerns for certificate validation.",
                            evidence="No OCSP response received during TLS handshake",
                            remediation="Enable OCSP stapling on the web server to improve TLS performance and privacy.",
                            cwe="CWE-295",
                        ))
        except Exception:
            pass
        return results
