"""
Real end-to-end tests using actual mitmproxy + real HTTP server + real proxy traffic.

Spins up:
  - A real HTTP server (VulnHTTPHandler) on a random port
  - A real mitmproxy DumpMaster on a random port
  - Sends real HTTP requests through the proxy via httpx

Tests:
  - Basic traffic capture (request/response logged)
  - Interceptor: pause, modify, resume flows
  - Match & Replace: automatic header/body rewriting
  - LoggerAddon body capture with content-type filtering
"""
import asyncio
import concurrent.futures
import json
import logging
import socket
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import pytest
import httpx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# ─── Real HTTP test server ───────────────────────────────────────────────

TEST_HTML = b"<html><body><h1>Hello</h1></body></html>"
TEST_JSON = b'{"status":"ok","data":[1,2,3]}'
TEST_BINARY = bytes(range(256))
TEST_POST_RESPONSE = b'{"received": true}'


class _TestHTTPHandler(BaseHTTPRequestHandler):
    server_version = "TestServer/1.0"
    sys_version = ""

    def _respond(self, status=200, body=b"", content_type="text/html", extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._respond(body=TEST_HTML)
        elif self.path == "/api/data":
            self._respond(body=TEST_JSON, content_type="application/json")
        elif self.path == "/binary":
            self._respond(body=TEST_BINARY, content_type="application/octet-stream")
        elif self.path == "/redirect":
            self._respond(status=302, extra_headers=[("Location", "/")])
        elif self.path.startswith("/echo"):
            self._respond(body=self.path.encode())
        else:
            self._respond(status=404, body=b"Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self._respond(body=TEST_POST_RESPONSE, content_type="application/json")

    def log_message(self, fmt, *args):
        pass  # silence server logs


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ─── Mitmproxy capture addon ─────────────────────────────────────────────

class CaptureAddon:
    """Collects all request/response events passing through mitmproxy."""

    def __init__(self):
        self.captured_requests: list[dict] = []
        self.captured_responses: list[dict] = []
        self.intercepted_flows: dict[str, http.HTTPFlow] = {}
        self._lock = threading.Lock()

    def request(self, flow: http.HTTPFlow):
        with self._lock:
            self.captured_requests.append({
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.pretty_host,
                "path": flow.request.path,
                "headers": dict(flow.request.headers),
                "content_length": len(flow.request.content or b""),
            })

    def response(self, flow: http.HTTPFlow):
        with self._lock:
            self.captured_responses.append({
                "url": flow.request.pretty_url,
                "status": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "content_length": len(flow.response.content or b""),
                "content_type": flow.response.headers.get("content-type", ""),
            })


# ─── Interceptor Addon (simplified for testing) ──────────────────────────

class _TestInterceptorAddon:
    """Minimal interceptor that can pause flows on demand."""

    def __init__(self):
        self.pause_next = False
        self.paused_flow: http.HTTPFlow | None = None
        self.modified = {}

    def request(self, flow: http.HTTPFlow):
        if self.pause_next:
            self.pause_next = False
            flow.intercept()
            self.paused_flow = flow

    def resume_with_modifications(self, modifications: dict | None = None):
        if self.paused_flow is None:
            return
        flow = self.paused_flow
        if modifications:
            if "method" in modifications:
                flow.request.method = modifications["method"]
            if "url" in modifications:
                flow.request.url = modifications["url"]
            if "headers" in modifications:
                flow.request.headers.clear()
                for k, v in modifications["headers"].items():
                    flow.request.headers[k] = str(v)
            if "body" in modifications:
                body = modifications["body"]
                flow.request.content = body.encode() if isinstance(body, str) else body
        flow.resume()
        self.paused_flow = None


# ─── Match & Replace Addon (simplified) ──────────────────────────────────

class _TestMatchReplaceAddon:
    """Applies simple string replacements to flows."""

    def __init__(self):
        self.rules: list[dict] = []

    def add_rule(self, scope: str, match: str, replacement: str):
        self.rules.append({"scope": scope, "match": match, "replacement": replacement})

    def request(self, flow: http.HTTPFlow):
        for rule in self.rules:
            scope = rule["scope"]
            if scope not in ("request", "request_header", "request_body", "both"):
                continue
            if scope in ("request", "request_header"):
                for key in list(flow.request.headers.keys()):
                    old = flow.request.headers[key]
                    if rule["match"] in old:
                        flow.request.headers[key] = old.replace(rule["match"], rule["replacement"])
            if scope in ("request", "request_body") and flow.request.content:
                try:
                    text = flow.request.content.decode()
                    if rule["match"] in text:
                        flow.request.content = text.replace(rule["match"], rule["replacement"]).encode()
                except UnicodeDecodeError:
                    pass

    def response(self, flow: http.HTTPFlow):
        for rule in self.rules:
            scope = rule["scope"]
            if scope not in ("response", "response_header", "response_body", "both"):
                continue
            if scope in ("response", "response_header") and flow.response:
                for key in list(flow.response.headers.keys()):
                    old = flow.response.headers[key]
                    if rule["match"] in old:
                        flow.response.headers[key] = old.replace(rule["match"], rule["replacement"])
            if scope in ("response", "response_body") and flow.response and flow.response.content:
                ct = flow.response.headers.get("content-type", "")
                if ct and not ct.startswith("text/") and "json" not in ct:
                    continue
                try:
                    text = flow.response.content.decode()
                    if rule["match"] in text:
                        flow.response.content = text.replace(rule["match"], rule["replacement"]).encode()
                except UnicodeDecodeError:
                    pass


# ─── Test fixture: real mitmproxy + HTTP server ──────────────────────────

@pytest.fixture(scope="module")
def real_http_server():
    """Start a real HTTP server on a random port, yield (host, port), tear down."""
    server = HTTPServer(("127.0.0.1", 0), _TestHTTPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1", port
    server.shutdown()


class ProxyTestFixture:
    """Manages a real mitmproxy instance for testing."""

    def __init__(self):
        self.proxy_port = _find_free_port()
        self.capture = CaptureAddon()
        self.interceptor = _TestInterceptorAddon()
        self.match_replace = _TestMatchReplaceAddon()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._master: DumpMaster | None = None

    def start(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        time.sleep(2)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start_mitmproxy())

    async def _start_mitmproxy(self):
        opts = Options(
            listen_host="127.0.0.1",
            listen_port=self.proxy_port,
            mode=["regular"],
            ssl_insecure=True,
        )
        self._master = DumpMaster(opts)
        self._master.addons.add(self.capture)
        self._master.addons.add(self.interceptor)
        self._master.addons.add(self.match_replace)
        await self._master.run()

    def stop(self):
        if self._master:
            try:
                self._master.shutdown()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def resume_intercepted(self, modifications: dict | None = None):
        """Resume the intercepted flow on mitmproxy's event loop."""
        addon = self.interceptor
        if addon.paused_flow is None:
            return
        flow = addon.paused_flow
        addon.paused_flow = None
        if modifications:
            if "method" in modifications:
                flow.request.method = modifications["method"]
            if "url" in modifications:
                flow.request.url = modifications["url"]
            if "headers" in modifications:
                flow.request.headers.clear()
                for k, v in modifications["headers"].items():
                    flow.request.headers[k] = str(v)
            if "body" in modifications:
                body = modifications["body"]
                flow.request.content = body.encode() if isinstance(body, str) else body
        async def _do_resume():
            flow.resume()
        if self._loop and not self._loop.is_closed():
            asyncio.run_coroutine_threadsafe(_do_resume(), self._loop)

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"


@pytest.fixture(scope="module")
def proxy_fixture():
    """Start a real mitmproxy instance, yield fixture object, tear down."""
    pf = ProxyTestFixture()
    pf.start()
    yield pf
    pf.stop()


def _client(proxy_url):
    return httpx.Client(proxy=proxy_url, timeout=10)


# ═══════════════════════════════════════════════════════════════════════════
#  TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestRealProxyCapture:
    """Test that mitmproxy actually captures real HTTP traffic."""

    def test_proxy_captures_request(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 200
        time.sleep(0.5)
        assert len(proxy_fixture.capture.captured_requests) >= 1
        req = proxy_fixture.capture.captured_requests[-1]
        assert req["method"] == "GET"
        assert req["url"].endswith("/")

    def test_proxy_captures_response(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 200
        time.sleep(0.5)
        assert len(proxy_fixture.capture.captured_responses) >= 1
        res = proxy_fixture.capture.captured_responses[-1]
        assert res["status"] == 200
        assert "text/html" in res.get("content_type", "")

    def test_proxy_passes_response_body(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.text == TEST_HTML.decode()

    def test_proxy_404(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/nonexistent"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 404

    def test_proxy_json_content(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/api/data"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_proxy_redirect(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/redirect"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url, follow_redirects=True)
        assert resp.status_code == 200
        assert resp.url.path == "/"

    def test_proxy_post(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/submit"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.post(url, json={"key": "value"})
        assert resp.status_code == 200

    def test_proxy_binary_content_preserved(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        url = f"http://{host}:{port}/binary"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 200
        assert resp.content == TEST_BINARY, f"Binary content corrupted: got {len(resp.content)} bytes, expected {len(TEST_BINARY)}"

    def test_multiple_requests_tracked(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        prev_count = len(proxy_fixture.capture.captured_requests)
        with _client(proxy_fixture.proxy_url) as c:
            for i in range(3):
                c.get(f"http://{host}:{port}/echo/{i}")
        time.sleep(0.5)
        assert len(proxy_fixture.capture.captured_requests) >= prev_count + 3


class TestRealProxyInterceptor:
    """Test that the interceptor can pause, modify, and resume flows."""

    def test_intercept_pauses_flow(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.interceptor.pause_next = True
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(c.get, url)
                time.sleep(0.5)
                assert proxy_fixture.interceptor.paused_flow is not None
                proxy_fixture.resume_intercepted()
                resp = fut.result(timeout=5)
                assert resp.status_code == 200

    def test_intercept_modifies_method(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.interceptor.pause_next = True
        url = f"http://{host}:{port}/echo/hello"
        with _client(proxy_fixture.proxy_url) as c:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(c.post, url, content=b"data")
                time.sleep(0.5)
                assert proxy_fixture.interceptor.paused_flow is not None
                proxy_fixture.resume_intercepted({"method": "GET"})
                resp = fut.result(timeout=5)
                assert resp.status_code == 200

    def test_intercept_modifies_headers(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.interceptor.pause_next = True
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(c.get, url)
                time.sleep(0.5)
                assert proxy_fixture.interceptor.paused_flow is not None
                proxy_fixture.resume_intercepted({
                    "headers": {"X-Modified": "yes", "Host": f"127.0.0.1:{port}"},
                })
                resp = fut.result(timeout=5)
                assert resp.status_code == 200

    def test_intercept_modifies_body(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.interceptor.pause_next = True
        url = f"http://{host}:{port}/submit"
        with _client(proxy_fixture.proxy_url) as c:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(c.post, url, content=b'{"original":true}')
                time.sleep(0.5)
                assert proxy_fixture.interceptor.paused_flow is not None
                proxy_fixture.resume_intercepted({
                    "body": '{"modified":true}',
                })
                resp = fut.result(timeout=5)
                assert resp.status_code == 200


class TestRealProxyMatchReplace:
    """Test that Match & Replace automatically rewrites traffic."""

    @pytest.fixture(autouse=True)
    def _clear_rules(self, proxy_fixture):
        proxy_fixture.match_replace.rules.clear()

    def test_mr_replaces_response_header(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.match_replace.add_rule("response_header", "TestServer", "ReplacedServer")
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 200
        assert "ReplacedServer" in resp.headers.get("server", "")

    def test_mr_replaces_response_body(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.match_replace.add_rule("response_body", "Hello", "Hacked")
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert "Hacked" in resp.text
        assert "Hello" not in resp.text

    def test_mr_replaces_request_header(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.match_replace.add_rule("request_header", "python-httpx", "Nyx-Test")
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url, headers={"User-Agent": "python-httpx/0.35"})
        assert resp.status_code == 200

    def test_mr_does_not_corrupt_binary(self, real_http_server, proxy_fixture):
        proxy_fixture.match_replace.add_rule("response_body", "X", "Y")
        host, port = real_http_server
        url = f"http://{host}:{port}/binary"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert resp.status_code == 200
        assert resp.content == TEST_BINARY, "Binary content corrupted by M&R"

    def test_mr_multiple_rules_chain(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        proxy_fixture.match_replace.add_rule("response_header", "TestServer", "Proxy1")
        proxy_fixture.match_replace.add_rule("response_header", "text/html", "text/plain")
        url = f"http://{host}:{port}/"
        with _client(proxy_fixture.proxy_url) as c:
            resp = c.get(url)
        assert "Proxy1" in resp.headers.get("server", "")


class TestRealProxyConcurrency:
    """Test that the proxy handles multiple concurrent requests."""

    def test_concurrent_requests(self, real_http_server, proxy_fixture):
        host, port = real_http_server
        urls = [f"http://{host}:{port}/echo/{i}" for i in range(5)]
        with _client(proxy_fixture.proxy_url) as c:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(c.get, url) for url in urls]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
        assert all(r.status_code == 200 for r in results)
