"""DNS protocol decoder."""
import logging
import struct
from datetime import datetime
from typing import Iterator, Optional

from core.network.protocols.base import ProtocolDecoder, ProtocolFrame, UDPFlow, TCPStream, FiveTuple

logger = logging.getLogger(__name__)


class DNSDecoder(ProtocolDecoder):
    """DNS protocol decoder for UDP and TCP."""

    name = "dns"
    ports = {53, 5353, 853}

    def can_decode(self, stream: UDPFlow | TCPStream) -> bool:
        if isinstance(stream, UDPFlow):
            return True
        if isinstance(stream, TCPStream) and stream.frames:
            first = stream.frames[0]
            if len(first.payload) >= 2:
                length = struct.unpack(">H", first.payload[:2])[0]
                return len(first.payload) >= 2 + length
        return False

    def decode(self, stream: UDPFlow | TCPStream) -> Iterator[ProtocolFrame]:
        if isinstance(stream, UDPFlow):
            yield from self._decode_udp(stream)
        else:
            yield from self._decode_tcp(stream)

    def _decode_udp(self, flow: UDPFlow) -> Iterator[ProtocolFrame]:
        for pkt in flow.packets:
            if not pkt.payload:
                continue
            parsed = self._parse_dns(pkt.payload)
            if parsed:
                yield ProtocolFrame(
                    frame_type="dns",
                    timestamp=pkt.timestamp,
                    data=parsed,
                    raw_ref=pkt.payload,
                    five_tuple=flow.five_tuple
                )

    def _decode_tcp(self, stream) -> Iterator[ProtocolFrame]:
        buffer = b""
        for frame in stream.frames:
            if not frame.payload:
                continue
            buffer += frame.payload

            while len(buffer) >= 2:
                length = struct.unpack(">H", buffer[:2])[0]
                if len(buffer) < 2 + length:
                    break
                dns_data = buffer[2:2+length]
                buffer = buffer[2+length:]

                parsed = self._parse_dns(dns_data)
                if parsed:
                    yield ProtocolFrame(
                        frame_type="dns",
                        timestamp=frame.timestamp,
                        data=parsed,
                        raw_ref=dns_data,
                        five_tuple=stream.five_tuple
                    )

    def _parse_dns(self, data: bytes) -> Optional[dict]:
        try:
            if len(data) < 12:
                return None

            header = struct.unpack(">HHHHHH", data[:12])
            transaction_id, flags, qdcount, ancount, nscount, arcount = header

            is_query = (flags & 0x8000) == 0
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF

            offset = 12
            questions = []
            for _ in range(qdcount):
                name, offset = self._parse_name(data, offset)
                if name is None:
                    return None
                qtype, qclass = struct.unpack(">HH", data[offset:offset+4])
                offset += 4
                questions.append({"name": name, "type": qtype, "class": qclass})

            answers = []
            for _ in range(ancount):
                name, offset = self._parse_name(data, offset)
                if name is None:
                    break
                atype, aclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
                offset += 10
                rdata = data[offset:offset+rdlength]
                offset += rdlength
                answers.append({
                    "name": name,
                    "type": atype,
                    "class": aclass,
                    "ttl": ttl,
                    "data": self._format_rdata(atype, rdata)
                })

            return {
                "transaction_id": transaction_id,
                "is_query": is_query,
                "opcode": opcode,
                "rcode": rcode,
                "questions": questions,
                "answers": answers,
            }
        except Exception as e:
            logger.debug("DNS parse error: %s", e)
            return None

    def _parse_name(self, data: bytes, offset: int) -> tuple[Optional[str], int]:
        labels = []
        visited: set[int] = set()
        while offset < len(data):
            if offset in visited:
                return None, offset
            visited.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    return None, offset
                pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
                name, _ = self._parse_name(data, pointer)
                return name, offset + 2
            offset += 1
            if offset + length > len(data):
                return None, offset
            labels.append(data[offset:offset+length].decode("utf-8", errors="replace"))
            offset += length
        return ".".join(labels), offset

    def _format_rdata(self, rtype: int, rdata: bytes) -> str:
        if rtype == 1 and len(rdata) == 4:
            return ".".join(str(b) for b in rdata)
        if rtype == 28 and len(rdata) == 16:
            parts = [rdata[i:i+2].hex() for i in range(0, 16, 2)]
            return ":".join(parts)
        if rtype in (2, 5, 12):
            name, _ = self._parse_name(rdata, 0)
            return name or ""
        return rdata.hex()