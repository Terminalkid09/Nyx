"""Bridge between the network layer and mitmproxy.

HTTP/TLS parsing is mitmproxy's job, not the network layer's: the packet view
links to the flows LoggerAddon already captures (see api/routes/network.py).
What the network layer still needs from TLS is a single piece of metadata —
the SNI, so streams can be labelled "TLS -> example.com" without touching
mitmproxy. That is a ~30-line parser, not a decoder framework.
"""
import logging
import struct
from typing import Iterator, Optional

from core.network.protocols.base import TCPStream

logger = logging.getLogger(__name__)


def extract_sni_from_payload(client_hello: bytes) -> Optional[str]:
    """Extract the SNI from a TLS 1.2/1.3 ClientHello body.

    Walks the handshake structure (session id, cipher suites, compression
    methods, extensions) and returns the first host_name (extension type 0)
    server-name entry. Returns None when the payload is not a ClientHello
    or carries no SNI.
    """
    try:
        if len(client_hello) < 34:
            return None
        offset = 34  # legacy_version(2) + random(32)

        session_id_len = client_hello[offset]
        offset += 1 + session_id_len

        if offset + 2 > len(client_hello):
            return None
        cipher_suites_len = int.from_bytes(client_hello[offset:offset + 2], "big")
        offset += 2 + cipher_suites_len

        if offset >= len(client_hello):
            return None
        compression_methods_len = client_hello[offset]
        offset += 1 + compression_methods_len

        if offset + 2 > len(client_hello):
            return None
        extensions_len = int.from_bytes(client_hello[offset:offset + 2], "big")
        offset += 2
        extensions_end = offset + extensions_len

        while offset + 4 <= extensions_end and offset < len(client_hello):
            ext_type, ext_len = struct.unpack(">HH", client_hello[offset:offset + 4])
            offset += 4
            if ext_type == 0:  # server_name
                if offset + 2 > len(client_hello):
                    break
                sni_list_len = int.from_bytes(client_hello[offset:offset + 2], "big")
                offset += 2
                while offset + 3 <= len(client_hello):
                    # Each server-name entry is (type:1, length:2, value:len).
                    # The old walk skipped only 1 byte for non-host_name
                    # entries — landing in the MIDDLE of the entry's value and
                    # reading garbage as the next type. Always advance past
                    # the full (type + length + value).
                    sni_type = client_hello[offset]
                    sni_len = int.from_bytes(client_hello[offset + 1:offset + 3], "big")
                    if offset + 3 + sni_len > len(client_hello):
                        return None
                    value = client_hello[offset + 3:offset + 3 + sni_len]
                    offset += 3 + sni_len
                    if sni_type == 0:  # host_name
                        return value.decode("utf-8", errors="replace")
                break
            offset += ext_len
    except Exception as e:
        logger.debug("SNI extraction error: %s", e)
    return None


def extract_sni_from_stream(stream: TCPStream) -> Optional[str]:
    """Extract SNI from the first client-side TLS handshake of a stream."""
    if stream.five_tuple.dst_port not in (443, 8443, 9443, 993, 995, 5223, 8883):
        return None
    for frame in stream.frames:
        if not frame.is_client or not frame.payload:
            continue
        payload = frame.payload
        # Walk TLS records looking for a handshake (type 22) record whose
        # first handshake message is ClientHello (type 1).
        offset = 0
        while offset + 5 <= len(payload):
            content_type, _version, length = struct.unpack(">BHH", payload[offset:offset + 5])
            body = payload[offset + 5:offset + 5 + length]
            if content_type == 22 and len(body) >= 4 and body[0] == 1:
                msg_len = int.from_bytes(body[1:4], "big")
                client_hello = body[4:4 + msg_len]
                sni = extract_sni_from_payload(client_hello)
                if sni:
                    return sni
            offset += 5 + length
    return None


def _iter_tls_records(payload: bytes):
    offset = 0
    while offset + 5 <= len(payload):
        content_type, _version, length = struct.unpack(">BHH", payload[offset:offset + 5])
        yield content_type, payload[offset + 5:offset + 5 + length]
        offset += 5 + length


def feed_mitmproxy_from_stream(stream: TCPStream, sni: str) -> None:
    """Feed a reconstructed TCP stream into mitmproxy for TLS MITM and HTTP parsing.

    Bridge point kept for the design's end-to-end flow: the network layer
    captures passively while mitmproxy stays the active interceptor. Real
    injection into mitmproxy's internal TCP layer depends on private APIs
    that change between versions, so this degrades to a logged summary
    instead of pretending to replay frames.
    """
    try:
        client_bytes = sum(len(f.payload) for f in stream.frames if f.is_client)
        server_bytes = sum(len(f.payload) for f in stream.frames if not f.is_client)
        logger.info(
            "Stream %s:%d -> %s:%d (%s): %dB client / %dB server — handled by "
            "mitmproxy via the Proxy tab, not re-injected",
            stream.five_tuple.src_ip, stream.five_tuple.src_port,
            stream.five_tuple.dst_ip, stream.five_tuple.dst_port,
            sni or "no-SNI",
            client_bytes, server_bytes,
        )
    except Exception as e:
        logger.debug("Stream bridge note failed: %s", e)
