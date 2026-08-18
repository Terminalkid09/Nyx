"""QUIC protocol decoder (best-effort)."""
import logging
from datetime import datetime
from typing import Iterator, Optional

from core.network.protocols.base import ProtocolDecoder, ProtocolFrame, UDPFlow, TCPStream, FiveTuple

logger = logging.getLogger(__name__)


class QUICDecoder(ProtocolDecoder):
    """QUIC frame decoder - minimal implementation for version negotiation and handshake detection."""

    name = "quic"
    ports = {443, 8443}

    def can_decode(self, stream: UDPFlow | TCPStream) -> bool:
        if not isinstance(stream, UDPFlow):
            return False
        if not stream.packets:
            return False
        first = stream.packets[0]
        if not first.payload or len(first.payload) < 5:
            return False
        first_byte = first.payload[0]
        is_long_header = (first_byte & 0x80) != 0
        version = int.from_bytes(first.payload[1:5], "big")
        return is_long_header and version in (0x00000001, 0x00000002, 0xFF00001D, 0xFF000020, 0xFF000021, 0xFF000022)

    def decode(self, stream: UDPFlow) -> Iterator[ProtocolFrame]:
        for pkt in stream.packets:
            if not pkt.payload:
                continue
            parsed = self._parse_quic(pkt.payload)
            if parsed:
                yield ProtocolFrame(
                    frame_type="quic",
                    timestamp=pkt.timestamp,
                    data=parsed,
                    raw_ref=pkt.payload,
                    five_tuple=stream.five_tuple
                )

    def _parse_quic(self, data: bytes) -> Optional[dict]:
        if len(data) < 1:
            return None

        first_byte = data[0]
        is_long_header = (first_byte & 0x80) != 0

        if is_long_header:
            return self._parse_long_header(data)
        else:
            return self._parse_short_header(data)

    def _parse_long_header(self, data: bytes) -> Optional[dict]:
        if len(data) < 7:
            return None

        first_byte = data[0]
        version = int.from_bytes(data[1:5], "big")
        dcil = data[5]
        scil = data[6]
        offset = 7

        if offset + dcil > len(data):
            return None
        dcid = data[offset:offset+dcil].hex()
        offset += dcil

        if offset + scil > len(data):
            return None
        scid = data[offset:offset+scil].hex()
        offset += scil

        packet_type = first_byte & 0x30

        type_names = {
            0x00: "initial",
            0x10: "0rtt",
            0x20: "handshake",
            0x30: "retry",
        }

        return {
            "header_form": "long",
            "packet_type": type_names.get(packet_type, f"unknown({packet_type:02x})"),
            "version": version,
            "dcid": dcid,
            "scid": scid,
            "remaining_length": len(data) - offset,
        }

    def _parse_short_header(self, data: bytes) -> Optional[dict]:
        if len(data) < 1:
            return None

        first_byte = data[0]
        spin_bit = (first_byte & 0x40) != 0
        key_phase = (first_byte & 0x04) != 0
        pn_length = (first_byte & 0x03) + 1

        return {
            "header_form": "short",
            "spin_bit": spin_bit,
            "key_phase": key_phase,
            "packet_number_length": pn_length,
        }