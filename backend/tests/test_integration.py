import pytest
import json
import threading
import socket
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler


VULNERABLE_HTML = b"""
<html><body>
<form action="/login" method="POST">
  <input name="user" value="admin">
  <input name="pass" type="password">
</form>
<script>var x = location.hash;</script>
</body></html>
"""

ERROR_SQL = "you have an error in your sql syntax near ''"
PASSWD_CONTENT = "root:x:0:0:root:/root:/root/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
JINJA_RESULT = "Hello 49"


class VulnHTTPHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.20.1"
    sys_version = ""

    def _respond(self, status=200, body=b"", content_type=b"text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Powered-By", "PHP/7.4")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        if "sqli" in self.path:
            if "id" in params and ("'" in params["id"] or "1=1" in params["id"]):
                return self._respond(body=ERROR_SQL.encode())
            else:
                return self._respond(body=b"User: test")
        elif "xss" in self.path:
            if "q" in params:
                body = (params["q"] + " triggered").encode()
                return self._respond(body=body)
            else:
                return self._respond(body=VULNERABLE_HTML)
        elif "traversal" in self.path:
            if "file" in params and "passwd" in params["file"]:
                return self._respond(body=PASSWD_CONTENT.encode())
            else:
                return self._respond(body=b"not found")
        elif "ssti" in self.path:
            if "name" in params and params["name"] == "{{7*7}}":
                return self._respond(body=JINJA_RESULT.encode())
            elif "name" in params:
                return self._respond(body=f"Hello {params['name']}".encode())
            else:
                return self._respond(body=b"Hello world")
        elif "cmd" in self.path:
            if "cmd" in params:
                return self._respond(body=f"output of: {params['cmd']}".encode())
            else:
                return self._respond(body=b"ok")
        elif "redirect" in self.path:
            if "url" in params:
                return self._respond(status=302, extra_headers=[("Location", params["url"])])
            else:
                return self._respond(body=b"ok")
        elif "git" in self.path or ".git" in self.path:
            return self._respond(body=b"ref: refs/heads/main\n")
        elif self.path.rstrip("/") == "/dir":
            return self._respond(body=b"<html><body><h1>Index of /</h1><a href='../'>Parent Directory</a></body></html>")
        elif "upload" in self.path:
            return self._respond(body=b'{"status": "uploaded", "file": "payload.svg"}')
        elif "cors" in self.path:
            return self._respond(
                body=b"ok",
                extra_headers=[
                    ("Access-Control-Allow-Origin", "*"),
                    ("Access-Control-Allow-Credentials", "true"),
                ],
            )
        elif "headers" in self.path:
            return self._respond(body=str(self.headers).encode())
        elif "health" in self.path or "status" in self.path:
            return self._respond(body=b'{"status": "healthy"}')
        elif "admin" in self.path:
            return self._respond(body=b"<html><body><h1>Admin Panel</h1></body></html>")
        elif "metrics" in self.path:
            return self._respond(
                body=b"# HELP go_goroutines Number of goroutines\n# TYPE go_goroutines gauge\ngo_goroutines 42\nhttp_requests_total 100"
            )
        elif self.path.rstrip("/") == "":
            return self._respond(body=b"<html><body><h1>Index of /</h1><a href='../'>Parent Directory</a></body></html>")
        else:
            return self._respond(body=VULNERABLE_HTML)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        if "upload" in self.path:
            return self._respond(body=b'{"status": "uploaded", "file": "payload.svg"}')
        return self._respond(body=b"OK")

    def do_OPTIONS(self):
        return self._respond(body=b"OK")

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass


@pytest.fixture(scope="function")
def vuln_server():
    server = HTTPServer(("127.0.0.1", 0), VulnHTTPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    thread.join(timeout=5)


class TestIntegrationE2E:
    def test_server_responds(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/", timeout=10)
        assert resp.status_code == 200
        assert "html" in resp.text.lower()

    def test_manual_sqli_detection(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/sqli?id=1' OR '1'='1", timeout=10)
        assert resp.status_code == 200
        assert "error" in resp.text.lower() or "syntax" in resp.text.lower()

    def test_manual_xss_detection(self, vuln_server):
        import httpx
        payload = "<script>alert(1)</script>"
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/xss?q={payload}", timeout=10)
        assert resp.status_code == 200
        assert payload in resp.text

    def test_manual_traversal_detection(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/traversal?file=../../etc/passwd", timeout=10)
        assert resp.status_code == 200
        assert "root:x:" in resp.text

    def test_manual_ssti_detection(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/ssti?name={{{{7*7}}}}", timeout=10)
        assert resp.status_code == 200
        assert "Hello 49" in resp.text

    def test_manual_git_exposed(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/.git/HEAD", timeout=10)
        assert resp.status_code == 200
        assert "ref: refs/heads/main" in resp.text

    def test_manual_dir_listing(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/dir/", timeout=10)
        assert resp.status_code == 200
        assert "Index of" in resp.text

    def test_manual_cors_origin(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/cors", timeout=10)
        assert resp.status_code == 200
        assert resp.headers.get("access-control-allow-origin") == "*"

    def test_manual_prometheus_metrics(self, vuln_server):
        import httpx
        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/metrics", timeout=10)
        assert resp.status_code == 200
        assert "go_goroutines" in resp.text

    def test_active_scanner_sqli_detection(self, vuln_server):
        import asyncio
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        base = {
            "method": "GET",
            "url": f"http://127.0.0.1:{vuln_server}/sqli",
            "headers": {"Host": f"127.0.0.1:{vuln_server}"},
        }
        results = asyncio.run(scanner.run_checks(base, ["id"]))
        sqli = [r for r in results if "sqli" in r.get("check", "").lower() or "SQL" in r.get("title", "")]
        assert len(sqli) > 0, f"No SQLi findings: {results}"

    def test_scanner_fingerprint(self, vuln_server):
        import asyncio
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        fp = asyncio.run(scanner.fingerprint(f"http://127.0.0.1:{vuln_server}/"))
        assert fp["server"] == "nginx/1.20.1"
        assert "nginx" in fp["technologies"]

    def test_server_fingerprint_module(self, vuln_server):
        import asyncio
        from modules.scanner.fingerprint import fingerprint_server
        fp = asyncio.run(fingerprint_server(f"http://127.0.0.1:{vuln_server}/"))
        assert fp["version"] == "1.20.1"
        assert "nginx" in fp["technologies"]

    def test_auto_exploit_sqli(self, vuln_server):
        from modules.auto_exploit.engine import AutoExploitEngine
        engine = AutoExploitEngine()
        finding = {
            "cwe": "CWE-89",
            "url": f"http://127.0.0.1:{vuln_server}/sqli",
            "param": "id",
        }
        exploit = engine.generate_exploit(finding)
        assert exploit is not None
        assert exploit["cwe"] == "CWE-89"
        assert "target.com" not in exploit["code"]
        assert exploit["code"]
        assert exploit["extraction"] is not None

    def test_auto_exploit_multi_language(self, vuln_server):
        from modules.auto_exploit.engine import AutoExploitEngine
        engine = AutoExploitEngine()
        finding = {
            "cwe": "CWE-79",
            "url": f"http://127.0.0.1:{vuln_server}/xss",
            "param": "q",
        }
        for lang in ["curl", "python", "js", "html"]:
            exploit = engine.generate_exploit(finding, language=lang)
            assert exploit is not None, f"Failed for language {lang}"
            assert exploit["code"]

    def test_git_exposed_check(self, vuln_server):
        import asyncio
        from modules.scanner.active.checks.active_git_exposed import ActiveGitExposedCheck
        check = ActiveGitExposedCheck()
        base = {
            "method": "GET",
            "url": f"http://127.0.0.1:{vuln_server}/",
            "headers": {"Host": f"127.0.0.1:{vuln_server}"},
        }
        results = asyncio.run(check.run(base, []))
        git = [r for r in results if r.triggered]
        assert len(git) > 0

    def test_prometheus_check(self, vuln_server):
        import asyncio
        from modules.scanner.active.checks.active_prometheus_check import ActivePrometheusCheck
        check = ActivePrometheusCheck()
        base = {
            "method": "GET",
            "url": f"http://127.0.0.1:{vuln_server}/",
            "headers": {"Host": f"127.0.0.1:{vuln_server}"},
        }
        results = asyncio.run(check.run(base, []))
        prom = [r for r in results if r.triggered]
        assert len(prom) > 0

    def test_version_enum_check(self, vuln_server):
        import asyncio
        from modules.scanner.active.checks.active_version_enum import ActiveVersionEnumCheck
        check = ActiveVersionEnumCheck()
        base = {
            "method": "GET",
            "url": f"http://127.0.0.1:{vuln_server}/",
            "headers": {"Host": f"127.0.0.1:{vuln_server}"},
        }
        results = asyncio.run(check.run(base, []))
        ver = [r for r in results if r.triggered]
        assert len(ver) > 0

    def test_dir_listing_check(self, vuln_server):
        import asyncio
        from modules.scanner.active.checks.active_dir_listing import ActiveDirListingCheck
        check = ActiveDirListingCheck()
        base = {
            "method": "GET",
            "url": f"http://127.0.0.1:{vuln_server}/dir/",
            "headers": {"Host": f"127.0.0.1:{vuln_server}"},
        }
        results = asyncio.run(check.run(base, []))
        listing = [r for r in results if r.triggered]
        assert len(listing) > 0

    def test_full_scan_pipeline(self, vuln_server):
        import asyncio
        import httpx

        resp = httpx.get(f"http://127.0.0.1:{vuln_server}/", timeout=10)
        assert resp.status_code == 200

        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()

        fp = asyncio.run(scanner.fingerprint(f"http://127.0.0.1:{vuln_server}/"))
        assert "nginx" in fp["technologies"]

        base = {
            "method": "GET",
            "url": f"http://127.0.0.1:{vuln_server}/sqli",
            "headers": {"Host": f"127.0.0.1:{vuln_server}"},
        }
        results = asyncio.run(scanner.run_checks(base, ["id"]))
        assert len(results) > 0

        sqli = [r for r in results if r.get("triggered", False)]
        if sqli:
            from modules.auto_exploit.engine import AutoExploitEngine
            engine = AutoExploitEngine()
            exploit = engine.generate_exploit(sqli[0])
            assert exploit is not None

    @pytest.mark.skip(reason="Manual verification step - run after all automated tests pass")
    def test_manual_verification(self, vuln_server):
        """Convenience test to print the target URL for manual inspection."""
        import httpx
        print(f"\n=== MANUAL VERIFICATION ===")
        print(f"Target URL: http://127.0.0.1:{vuln_server}/")
        print(f"1. Open in browser: http://127.0.0.1:{vuln_server}/")
        print(f"2. Test SQLi: http://127.0.0.1:{vuln_server}/sqli?id=1' OR '1'='1")
        print(f"3. Test XSS: http://127.0.0.1:{vuln_server}/xss?q=<script>alert(1)</script>")
        print(f"4. Test traversal: http://127.0.0.1:{vuln_server}/traversal?file=../../etc/passwd")
        print(f"5. Test SSTI: http://127.0.0.1:{vuln_server}/ssti?name={{{{7*7}}}}")
        print(f"6. Test .git: http://127.0.0.1:{vuln_server}/.git/HEAD")
        print(f"7. Test dir listing: http://127.0.0.1:{vuln_server}/dir/")
        print(f"8. Test CORS: http://127.0.0.1:{vuln_server}/cors")
        print(f"9. Test Prometheus: http://127.0.0.1:{vuln_server}/metrics")
        print(f"=== END MANUAL VERIFICATION ===\n")
        assert True
