import time
import uuid
import logging
from typing import TYPE_CHECKING
from mitmproxy import http

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

_MAX_HEX_BYTES = 50 * 1024  # cap hex output to ~100KB chars


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
        if not self.engine.capture_active:
            return
        self._request_start_times[id(flow)] = time.monotonic()
        request_id = uuid.uuid4()
        flow.metadata["nyx_request_id"] = str(request_id)
        flow.metadata["nyx_session_id"] = self.engine.current_session_id

        body = self._safe_decode(flow.request.content, flow.request.headers.get("content-type", ""))
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
            "request_headers": dict(flow.request.headers),
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

        body = self._safe_decode(flow.response.content, flow.response.headers.get("content-type", ""))
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
            "headers": dict(flow.response.headers),
            "body": body,
            "content_type": flow.response.headers.get("content-type"),
            "size_bytes": len(flow.response.content),
            "response_time_ms": elapsed_ms,
            "is_body_truncated": truncated,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
            "request_body": self._safe_decode(flow.request.content, flow.request.headers.get("content-type", "")),
        }
        self.engine.emit_event(event)

    def _safe_decode(self, content: bytes | None, content_type: str = "") -> str | None:
        if not content:
            return None
        ct = content_type.lower().split(";")[0].strip() if content_type else ""
        if ct and not ct.startswith("text/") and ct not in (
            "application/json", "application/xml", "application/xhtml+xml",
            "application/javascript", "application/ld+json", "application/graphql",
        ):
            return content[:_MAX_HEX_BYTES].hex()
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return content[:_MAX_HEX_BYTES].hex()
