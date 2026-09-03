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

    def decode(self, stream: UDPFlow, start: int = 0, aggregate: bool = False) -> Iterator[ProtocolFrame]:
        """Yield QUIC frames for a flow.

        Per-packet mode (default, decode(flow)): one ProtocolFrame per QUIC
        datagram — noisy for real traffic, where the bulk of a connection is
        indistinguishable encrypted 'short' packets.

        Aggregated mode (aggregate=True): one summary frame per CONNECTION
        (keyed by DCID when available, else the five-tuple) with a packet
        count and per-type breakdown — mirrors how TCP streams display.
        """
        if aggregate:
            for frame in self._decode_aggregated(stream):
                yield frame
            return
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

    def _decode_aggregated(self, stream: UDPFlow) -> Iterator[ProtocolFrame]:
        """One summary frame per connection (DCID) within the flow."""
        from collections import OrderedDict

        groups: "OrderedDict[str, dict]" = OrderedDict()
        last_conn: Optional[str] = None
        ft = stream.five_tuple
        fallback_key = (
            f"{ft.src_ip}-{ft.dst_ip}-{ft.src_port}-{ft.dst_port}"
            if ft else "unknown"
        )
        for pkt in stream.packets:
            if not pkt.payload:
                continue
            parsed = self._parse_quic(pkt.payload)
            if not parsed:
                continue
            if parsed.get("dcid"):
                # Long header: carries the connection ID — switch attribution.
                key = parsed["dcid"]
                last_conn = key
            else:
                # Short header: no CID on the wire — belongs to the connection
                # of the most recent long-header packet in this flow.
                key = last_conn or fallback_key
            entry = groups.get(key)
            if entry is None:
                entry = {
                    "conn_id": key,
                    "five_tuple_fallback": fallback_key,
                    "first_seen": pkt.timestamp,
                    "packet_count": 0,
                    "packet_types": {},
                    "version": None,
                    "dcid": parsed.get("dcid"),
                }
                groups[key] = entry
            entry["packet_count"] += 1
            ptype = (
                parsed.get("packet_type", "short")
                if parsed.get("header_form") == "long"
                else "short"
            )
            entry["packet_types"][ptype] = entry["packet_types"].get(ptype, 0) + 1
            if entry["version"] is None and parsed.get("header_form") == "long":
                entry["version"] = parsed.get("version")

        for entry in groups.values():
            data = {
                "aggregated": True,
                "conn_id": entry["conn_id"],
                "dcid": entry["dcid"],
                "version": entry["version"],
                "packet_count": entry["packet_count"],
                "packet_types": entry["packet_types"],
                "note": (
                    f"{entry['packet_count']} QUIC datagrams on this "
                    "connection; payloads are encrypted"
                ),
            }
            yield ProtocolFrame(
                frame_type="quic",
                timestamp=entry["first_seen"],
                data=data,
                raw_ref=b"",
                five_tuple=stream.five_tuple,
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