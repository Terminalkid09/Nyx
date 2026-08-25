import time
import uuid
import logging
from typing import TYPE_CHECKING
from mitmproxy import http

from core.utils.text import safe_decode

if TYPE_CHECKING:
    from core.proxy.engine import ProxyEngine

logger = logging.getLogger(__name__)

SELF_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

NOISE_DOMAINS = {
    "api.github.com", "github.com", "githubusercontent.com",
    "ocsp.int-x3.letsencrypt.org", "ocsp.digicert.com",
    "ctldl.windowsupdate.com", "download.windowsupdate.com",
    "www.msftconnecttest.com", "ipv6.msftconnecttest.com",
    "msftncsi.com", "www.msftncsi.com",
    "crl.microsoft.com", "crl3.digicert.com", "crl4.digicert.com",
}

NOISE_PATHS = {
    "/success.txt", "/connecttest.txt", "/ncsi.txt", "/generate_204",
}

# Header names that contain authentication material. The values are replaced
# with ``[REDACTED]`` before being written to persistent storage (DB) or
# broadcast over WebSocket — both of which outlive the process.
_SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-api-key",
    "proxy-authorization", "x-auth-token", "x-csrf-token",
    "x-xsrf-token", "session", "x-session-id",
}


def _redact_headers(headers: dict) -> dict:
    """Return a copy of *headers* with sensitive values replaced."""
    if not headers:
        return headers
    return {
        k: ("[REDACTED]" if k.lower() in _SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


class LoggerAddon:
    def __init__(self, engine: "ProxyEngine", max_body_size: int = 10 * 1024 * 1024):
        self.engine = engine
        self.max_body_size = max_body_size
        self._request_start_times: dict[int, float] = {}

    def _is_self_traffic(self, flow: http.HTTPFlow) -> bool:
        host = flow.request.pretty_host
        if host in SELF_HOSTS:
            return True
        port = flow.request.port
        if port == self.engine.port and host in (self.engine.host, "localhost", "127.0.0.1"):
            return True
        return False

    def _is_noise(self, flow: http.HTTPFlow) -> bool:
        host = flow.request.pretty_host.lower()
        if any(noise in host for noise in NOISE_DOMAINS):
            return True
        for p in NOISE_PATHS:
            if flow.request.path.rstrip("/") == p or flow.request.path.startswith(p + "?"):
                return True
        return False

    def request(self, flow: http.HTTPFlow):
        if self._is_self_traffic(flow):
            return
        if self._is_noise(flow):
            return
        # NOTE: We intentionally do NOT gate on capture_active here.
        # During transparent MITM (ARP/DHCP/NDP spoofing), the browser-based
        # capture toggle is irrelevant — target traffic flows through the proxy
        # at the OS level and MUST be logged for the MITM to be useful.
        # The toggle only affects the UI's "Pause capture" button for manual
        # proxy mode; transparent mode always captures.
        self._request_start_times[id(flow)] = time.monotonic()
        request_id = uuid.uuid4()
        flow.metadata["nyx_request_id"] = str(request_id)
        flow.metadata["nyx_session_id"] = self.engine.current_session_id

        # Prometheus metrics
        from core.metrics import registry as _metrics
        _metrics.inc("proxy_requests_total")
        if flow.request.scheme == "https":
            _metrics.inc("proxy_requests_https_total")

        body = safe_decode(flow.request.content, flow.request.headers.get("content-type", ""))
        truncated = False
        if body and len(body) > self.max_body_size:
            body = body[:self.max_body_size]
            truncated = True

        event = {
            "type": "request.captured",
            "request_id": request_id,
            "session_id": self.engine.current_session_id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "request_headers": _redact_headers(dict(flow.request.headers)),
            "request_body": body,
            "is_body_truncated": truncated,
        }
        self.engine.emit_event(event)

    def response(self, flow: http.HTTPFlow):
        if self._is_self_traffic(flow):
            return
        elapsed_ms = int(
            (time.monotonic() - self._request_start_times.pop(id(flow), time.monotonic())) * 1000
        )
        raw_id = flow.metadata.get("nyx_request_id")
        if not raw_id:
            return
        request_id = uuid.UUID(raw_id)

        # Prometheus metrics
        from core.metrics import registry as _metrics
        _metrics.inc("proxy_responses_total")
        if flow.response.status_code:
            if 200 <= flow.response.status_code < 300:
                _metrics.inc("proxy_responses_2xx_total")
            elif 400 <= flow.response.status_code < 500:
                _metrics.inc("proxy_responses_4xx_total")
            elif 500 <= flow.response.status_code < 600:
                _metrics.inc("proxy_responses_5xx_total")
        # This is a gauge holding the *last* response time (not a moving
        # average). The name "_last" avoids misleading Prometheus users.
        _metrics.set("proxy_response_time_ms_last", elapsed_ms)

        body = safe_decode(flow.response.content, flow.response.headers.get("content-type", ""))
        truncated = False
        if body and len(body) > self.max_body_size:
            body = body[:self.max_body_size]
            truncated = True

        event = {
            "type": "response.received",
            "request_id": request_id,
            "session_id": flow.metadata.get("nyx_session_id"),
            "status": flow.response.status_code,
            "reason": flow.response.reason,
            "headers": _redact_headers(dict(flow.response.headers)),
            "body": body,
            "content_type": flow.response.headers.get("content-type"),
            "size_bytes": len(flow.response.content),
            "response_time_ms": elapsed_ms,
            "is_body_truncated": truncated,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "request_headers": _redact_headers(dict(flow.request.headers)),
            "request_body": safe_decode(
                flow.request.content,
                flow.request.headers.get("content-type", ""),
            ),
        }
        self.engine.emit_event(event)
