"""Local deliberately-vulnerable target for Nyx live verification."""
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8099


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status: int, body: str, headers: dict | None = None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            payload = query.get("q", [""])[0]
            return self._send(200, f"<html><body>Results for {payload}</body></html>")

        if path == "/sqli":
            value = query.get("id", [""])[0]
            if "'" in value or "%27" in value:
                return self._send(
                    500,
                    "You have an error in your SQL syntax; check the manual that "
                    "corresponds to your MySQL server version",
                )
            return self._send(200, "<html>user id 1</html>")

        if path == "/.env":
            return self._send(200, "DB_PASSWORD=supersecret\nAWS_KEY=AKIAEXAMPLE\n")

        if path in ("/admin", "/admin/"):
            return self._send(200, "<html><body>Admin panel</body></html>")

        if path == "/redirect":
            return self._send(302, "", {"Location": "https://example.com/"})

        # Soft 404: unknown paths answer 200 with a generic page.
        return self._send(200, f"<html><body>Not found: {path}</body></html>")


if __name__ == "__main__":
    # Bind all interfaces so the test target can also be reached through the
    # Nyx proxy over the LAN IP: the capture addon drops loopback traffic as
    # "self" traffic, so a 127.0.0.1 target would never show up in the UI.
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
