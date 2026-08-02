"""On-demand, LAN-bound CA portal.

The QR endpoints in ``main.py`` encode a URL that a phone/camera scans. The
regular API binds to 127.0.0.1 only, so a separate lightweight HTTP server is
spawned on 0.0.0.0 just long enough to serve the CA certificate and its
install/uninstall pages. It is started lazily by the QR endpoints and shuts
itself down a short while after the page is abandoned (and immediately when
the scanned page reports it is being closed).
"""
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_PORT = int(os.environ.get("NYX_CA_PORTAL_PORT", "18081"))
IDLE_TIMEOUT_S = int(os.environ.get("NYX_CA_PORTAL_IDLE_S", "90"))
HEARTBEAT_EVERY_S = int(os.environ.get("NYX_CA_PORTAL_HEARTBEAT_S", "25"))

INSTALL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nyx — Install CA Certificate</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#030712;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:560px;width:90%;margin:20px;text-align:center}
h1{font-size:24px;font-weight:700;margin-top:0}
.btn{display:inline-block;background:#7c3aed;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-size:15px;font-weight:600;margin:8px 4px}
.btn:hover{background:#6d28d9}
.note{font-size:12px;color:#94a3b8;line-height:1.6;text-align:left;border-top:1px solid #334155;margin-top:20px;padding-top:16px}
code{background:#0f172a;padding:2px 6px;border-radius:4px}
#done{display:none;color:#34d399;font-weight:600;margin-top:14px}
</style>
</head>
<body>
<div class="card">
<h1>Nyx CA Certificate</h1>
<p>Download the certificate and install it on this device so Nyx can decrypt
HTTPS traffic.</p>
<a class="btn" href="/api/ca-certificate" download>Download Certificate</a>
<a class="btn" href="/api/ca-uninstall">Remove</a>
<div id="done">Certificate acknowledged — interception active.</div>
<div class="note">
<strong>Android:</strong> tap Download, then open the downloaded
<code>.pem</code> and follow the system prompt.<br>
<strong>iOS:</strong> download the cert, then go to
<code>Settings → General → About → Certificate Trust Settings</code> and switch
on <code>Nyx</code>.<br>
<strong>Windows/macOS:</strong> finish the same flow in the system certificate
store.
</div>
</div>
<script>
setInterval(function(){ fetch('/api/portal-heartbeat'); }, %HEARTBEAT_MS%);
window.addEventListener('beforeunload', function () {
  fetch('/api/portal-close', { keepalive: true });
});
var done = document.getElementById('done');
var ca = new URL('/api/ca-certificate', location.href);
fetch(ca, { method: 'HEAD' }).then(function (r) {
  if (r.status !== 200) { done.textContent = 'CA not found. Start the proxy first.'; done.style.display = 'block'; }
}).catch(function () {});
</script>
</body>
</html>
"""

UNINSTALL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nyx — Remove CA Certificate</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#030712;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:40px;max-width:560px;width:90%;margin:20px;text-align:center}
h1{font-size:24px;font-weight:700;margin-bottom:8px}
.btn{display:inline-block;background:#7c3aed;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-size:15px;font-weight:600;margin:8px 4px}
.btn:hover{background:#6d28d9}
code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:12px}
.note{font-size:12px;color:#94a3b8;line-height:1.7;text-align:left;border-top:1px solid #334155;margin-top:20px;padding-top:16px}
</style>
</head>
<body>
<div class="card">
<h1>Remove the CA Certificate</h1>
<p>Trusting the Nyx CA disables TLS integrity checks for it. Remove it when you
are done testing.</p>

<div class="note" style="padding-left:0;padding-right:0">
<div style="font-weight:600;margin-bottom:6px">Generic (most devices)</div>
<div style="margin-bottom:14px">
<a class="btn" href="/api/ca-uninstall-download" download>Download Removal Profile</a>
</div>

<b>Android:</b> <code>Settings → Lock screen &amp; security → Certificate
management → Remove</code><br><br>
<b>iOS:</b> <code>Settings → General → Profiles</code> and delete the Nyx
profile.<br><br>
<b>Windows:</b> <code>certmgr.msc → Trusted Root</code> and remove the
mitmproxy / Nyx entry.<br><br>
<b>macOS:</b> <code>Keychain Access → System</code> and delete the Nyx entry.
</div>
</div>
</body>
</html>
"""


class _PortalHandler(BaseHTTPRequestHandler):
    server_version = "NyxCAPortal/1.0"
    portal = None

    def log_message(self, fmt, *args):
        logger.debug("[ca-portal] " + fmt % args)

    def _send(self, code, body, content_type, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _not_found(self):
        self._send(404, b"not found", "text/plain")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/install", "/api/install", "/api/ca-install"):
            html = INSTALL_PAGE.replace("%HEARTBEAT_MS%", str(HEARTBEAT_EVERY_S * 1000))
            self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        elif path in ("/api/ca-uninstall", "/api/remove"):
            self._send(200, UNINSTALL_PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/ca-certificate":
            pem = None
            p = self.portal
            if p and p.cert_path and p.cert_path.exists():
                pem = p.cert_path.read_bytes()
            if pem is None:
                self._send(404, b"CA certificate not found", "text/plain")
            else:
                self._send(
                    200,
                    pem,
                    "application/x-pem-file",
                    extra={"Content-Disposition": "attachment; filename=mitmproxy-ca-cert.pem"},
                )
        elif path == "/api/health":
            self._send(200, b'{"ok":true}', "application/json")
        elif path == "/api/portal-heartbeat":
            p = self.portal
            if p:
                p.bump()
            self._send(200, b'{"ok":true}', "application/json")
        elif path == "/api/portal-close":
            p = self.portal
            if p:
                p.request_close()
            self._send(200, b'{"ok":true,"stopping":true}', "application/json")
        else:
            self._not_found()


class CAPortalManager:
    """Spawns an on-demand CA HTTPServer on a fixed LAN-reachable port."""

    def __init__(self, cert_path=None, port: int | None = None):
        self.cert_path = Path(cert_path) if cert_path else Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
        self.port = int(port or DEFAULT_PORT)
        self._httpd = None
        self._thread = None
        self._lock = threading.Lock()
        self._last_active = 0.0

    @property
    def running(self) -> bool:
        return self._httpd is not None

    @property
    def lan_port(self) -> int:
        return self.port

    def start(self) -> int | None:
        """Start the portal server. Returns the bound port, or None on failure."""
        if self._httpd is not None:
            with self._lock:
                self._last_active = time.time()
            return self.port
        try:
            httpd = ThreadingHTTPServer(("0.0.0.0", self.port), _PortalHandler)
            httpd.allow_reuse_address = True
            httpd.ca_portal = self
            _PortalHandler.portal = self
        except OSError as e:
            logger.error("CA portal bind failed on 0.0.0.0:%s: %s", self.port, e)
            return None
        self._httpd = httpd
        t = threading.Thread(target=httpd.serve_forever, name="ca-portal", daemon=True)
        self._thread = t
        t.start()
        with self._lock:
            self._last_active = time.time()
        # Background watchdog that stops a stale/idle server.
        threading.Thread(target=self._watchdog, name="ca-portal-watchdog", daemon=True).start()
        logger.info("CA portal server listening on 0.0.0.0:%s", self.port)
        return self.port

    def request_close(self):
        """Stop as soon as the current page closes (called from the handler)."""
        def closer():
            time.sleep(0.2)
            self.stop()
        threading.Thread(target=closer, name="ca-portal-closer", daemon=True).start()

    def bump(self):
        with self._lock:
            self._last_active = time.time()

    def _watchdog(self):
        while self._httpd is not None:
            time.sleep(1)
            with self._lock:
                idle = time.time() - self._last_active
            if idle >= IDLE_TIMEOUT_S:
                logger.info("CA portal idle for %ss — shutting down", IDLE_TIMEOUT_S)
                self.stop()
                return

    def stop(self):
        with self._lock:
            httpd = self._httpd
            self._httpd = None
            self._thread = None
        if httpd is None:
            return
        logger.info("Stopping CA portal server on 0.0.0.0:%s", self.port)
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception as e:
            logger.debug("CA portal shutdown: %s", e)


def start_portal(cert_path=None, port: int | None = None) -> CAPortalManager:
    mgr = CAPortalManager(cert_path=cert_path, port=port)
    mgr.start()
    return mgr