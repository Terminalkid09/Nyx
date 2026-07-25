from urllib.parse import urlparse
from modules.scanner.base_check import BaseCheck, CheckResult


class ActiveWeakCiphersCheck(BaseCheck):
    name = "active_weak_ciphers"

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
            weak_ciphers = ['RC4', 'DES', '3DES', 'IDEA', 'SEED', 'CBC', 'EXPORT', 'NULL', 'ANON']
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                results.append(CheckResult(
                                    triggered=True,
                                    severity="high",
                                    title="Weak Cipher Suite Detected",
                                    description=f"Server negotiated weak cipher: {cipher_name}. Weak ciphers like {weak} are vulnerable to attacks.",
                                    evidence=f"Cipher: {cipher_name}",
                                    remediation="Disable weak ciphers. Use only strong, modern cipher suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.",
                                    cwe="CWE-326",
                                ))
                                break
        except Exception:
            pass
        return results
