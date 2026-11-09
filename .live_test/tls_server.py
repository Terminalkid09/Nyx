"""Minimal HTTPS target for the MITM live check (self-signed certificate)."""
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 9443
CERT = Path(__file__).parent / "tls" / "cert.pem"
KEY = Path(__file__).parent / "tls" / "key.pem"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 — http.server API
        body = b"<html><body>TLS-SECRET-BODY</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"https target on 0.0.0.0:{PORT}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
