"""HTTP/1.1 + HTTP/2 frame decoder."""
import logging
import re
from datetime import datetime
from typing import Iterator, Optional

from core.network.protocols.base import ProtocolDecoder, ProtocolFrame, TCPStream, UDPFlow

logger = logging.getLogger(__name__)


class HTTPDecoder(ProtocolDecoder):
    """HTTP/1.1 and HTTP/2 frame decoder."""

    name = "http"
    ports = {80, 443, 8080, 8443, 8000, 8081, 8888, 9000}

    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        if not isinstance(stream, TCPStream):
            return False
        if not stream.frames:
            return False
        first = stream.frames[0]
        if not first.payload:
            return False
        payload = first.payload[:min(100, len(first.payload))]
        return b"HTTP/" in payload or b"GET " in payload or b"POST " in payload or b"HEAD " in payload

    def decode(self, stream: TCPStream | UDPFlow) -> Iterator[ProtocolFrame]:
        if isinstance(stream, TCPStream):
            yield from self._decode_http1(stream)
        else:
            yield from self._decode_http_udp(stream)

    def _decode_http1(self, stream: TCPStream) -> Iterator[ProtocolFrame]:
        client_buffer = b""
        server_buffer = b""
        for frame in stream.frames:
            if not frame.payload:
                continue
            buffer = client_buffer if frame.is_client else server_buffer
            buffer += frame.payload

            while True:
                request_end = self._find_http_end(buffer)
                if request_end == -1:
                    break

                http_data = buffer[:request_end]
                buffer = buffer[request_end:]

                if http_data.startswith(b"HTTP/"):
                    yield self._parse_response(http_data, frame.timestamp, stream.five_tuple)
                else:
                    yield self._parse_request(http_data, frame.timestamp, stream.five_tuple)

            if frame.is_client:
                client_buffer = buffer
            else:
                server_buffer = buffer

    def _find_http_end(self, data: bytes) -> int:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return -1
        header_end += 4

        headers = data[:header_end].decode("utf-8", errors="replace")
        content_length = 0
        for line in headers.split("\r\n"):
            if line.lower().startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except Exception:
                    pass

        if "transfer-encoding:" in headers.lower() and "chunked" in headers.lower():
            return self._find_chunked_end(data)

        total_len = header_end + content_length
        if len(data) >= total_len:
            return total_len
        return -1

    def _find_chunked_end(self, data: bytes) -> int:
        pos = data.find(b"\r\n\r\n")
        if pos == -1:
            return -1
        pos += 4
        while pos < len(data):
            line_end = data.find(b"\r\n", pos)
            if line_end == -1:
                return -1
            chunk_size_str = data[pos:line_end].decode("utf-8", errors="replace").strip().split(";")[0]
            try:
                chunk_size = int(chunk_size_str, 16)
            except Exception:
                return -1
            if chunk_size == 0:
                return line_end + 4
            pos = line_end + 2 + chunk_size + 2
        return -1

    def _parse_request(self, data: bytes, timestamp: datetime, five_tuple) -> ProtocolFrame:
        try:
            lines = data.split(b"\r\n")
            request_line = lines[0].decode("utf-8", errors="replace")
            parts = request_line.split(" ")
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""
            version = parts[2] if len(parts) > 2 else ""

            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.decode("utf-8", errors="replace").strip()] = v.decode("utf-8", errors="replace").strip()

            body_start = data.find(b"\r\n\r\n")
            body = data[body_start+4:] if body_start != -1 else b""

            return ProtocolFrame(
                frame_type="http_request",
                timestamp=timestamp,
                data={
                    "method": method,
                    "path": path,
                    "version": version,
                    "headers": headers,
                    "body_length": len(body),
                },
                raw_ref=data,
                five_tuple=five_tuple
            )
        except Exception:
            return ProtocolFrame(
                frame_type="http_request",
                timestamp=timestamp,
                data={"parse_error": True},
                raw_ref=data,
                five_tuple=five_tuple
            )

    def _parse_response(self, data: bytes, timestamp: datetime, five_tuple) -> ProtocolFrame:
        try:
            lines = data.split(b"\r\n")
            status_line = lines[0].decode("utf-8", errors="replace")
            parts = status_line.split(" ", 2)
            version = parts[0] if len(parts) > 0 else ""
            status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            reason = parts[2] if len(parts) > 2 else ""

            headers = {}
            for line in lines[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.decode("utf-8", errors="replace").strip()] = v.decode("utf-8", errors="replace").strip()

            body_start = data.find(b"\r\n\r\n")
            body = data[body_start+4:] if body_start != -1 else b""

            return ProtocolFrame(
                frame_type="http_response",
                timestamp=timestamp,
                data={
                    "version": version,
                    "status_code": status_code,
                    "reason": reason,
                    "headers": headers,
                    "body_length": len(body),
                },
                raw_ref=data,
                five_tuple=five_tuple
            )
        except Exception:
            return ProtocolFrame(
                frame_type="http_response",
                timestamp=timestamp,
                data={"parse_error": True},
                raw_ref=data,
                five_tuple=five_tuple
            )

    def _decode_http_udp(self, flow: UDPFlow) -> Iterator[ProtocolFrame]:
        for pkt in flow.packets:
            if not pkt.payload:
                continue
            yield ProtocolFrame(
                frame_type="http_udp_packet",
                timestamp=pkt.timestamp,
                data={"length": len(pkt.payload)},
                raw_ref=pkt.payload,
                five_tuple=flow.five_tuple
            )


class HTTP2Decoder(ProtocolDecoder):
    """HTTP/2 frame decoder (minimal)."""

    name = "http2"
    ports = {443, 8443, 8080}

    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        if not isinstance(stream, TCPStream):
            return False
        if not stream.frames:
            return False
        first = stream.frames[0]
        if not first.payload:
            return False
        return first.payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

    def decode(self, stream: TCPStream) -> Iterator[ProtocolFrame]:
        for frame in stream.frames:
            payload = frame.payload
            if not payload:
                continue
            if payload.startswith(b"PRI * HTTP/2.0"):
                # Strip the 24-byte client preface, keep parsing what follows
                # (typically the first SETTINGS frame in the same segment).
                payload = payload[24:]
            if not payload:
                continue

            offset = 0
            while offset + 9 <= len(payload):
                length = int.from_bytes(payload[offset:offset+3], "big")
                frame_type = payload[offset+3]
                flags = payload[offset+4]
                stream_id = int.from_bytes(payload[offset+5:offset+9], "big")
                frame_end = offset + 9 + length

                if frame_end > len(payload):
                    break

                frame_data = payload[offset+9:frame_end]

                yield ProtocolFrame(
                    frame_type="http2_frame",
                    timestamp=frame.timestamp,
                    data={
                        "frame_type": frame_type,
                        "flags": flags,
                        "stream_id": stream_id,
                        "length": length,
                    },
                    raw_ref=frame_data,
                    five_tuple=stream.five_tuple
                )

                offset = frame_end