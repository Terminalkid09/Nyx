from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActivePfsMissingCheck(BaseCheck):
    name = "active_pfs_missing"

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
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        if not any(kw in cipher_name for kw in ['ECDHE', 'DHE', 'EDH']):
                            results.append(CheckResult(
                                triggered=True,
                                severity="medium",
                                title="Missing Perfect Forward Secrecy",
                                description=f"Server uses {cipher_name} without ECDHE/DHE key exchange. Session keys can be decrypted if the private key is compromised.",
                                evidence=f"Cipher: {cipher_name}",
                                remediation="Prioritize ECDHE and DHE cipher suites. Disable static RSA key exchange.",
                                cwe="CWE-326",
                            ))
        except Exception:
            pass
        return results
