"""Scapy adapter decoders.

Nyx does NOT hand-write protocol parsers: DNS/DHCP/ARP/ICMP are decoded by
scapy itself (already a dependency — dns_spoof.py uses it the same way) and
re-wrapped as ProtocolFrames. HTTP/TLS is handled by mitmproxy, so the packet
view links to mitmproxy flows instead of parsing them (mitm_integration.py).
Each adapter is ~20-40 lines, not a 150-line parser.
"""
import logging
from typing import Iterator, Optional

from core.network.capture import RawPacket
from core.network.protocols.base import (
    FiveTuple,
    ProtocolDecoder,
    ProtocolFrame,
    TCPStream,
    UDPFlow,
)

logger = logging.getLogger(__name__)


def _qname(value) -> str:
    """Decode a scapy DNS name field to a plain dotted string."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value or "").rstrip(".")


def _rdata(rr) -> str:
    rd = getattr(rr, "rdata", "")
    if isinstance(rd, bytes):
        try:
            return rd.decode("utf-8", errors="replace").rstrip(".")
        except Exception:
            return rd.hex()
    return str(rd or "")


def _as_list(value):
    """scapy >= 2.6 exposes DNS qd/an/ns/ar as PacketListField(s); older
    versions expose a single element. Normalise to a list either way."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


class DNSDecoder(ProtocolDecoder):
    """DNS via scapy — UDP datagrams (port 53) and DNS-over-TCP streams."""

    name = "dns"
    ports = {53}

    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        return self._first_dns(stream) is not None

    def _parse(self, payload: bytes) -> Optional["object"]:
        try:
            from scapy.all import DNS
            if len(payload) < 12:
                return None
            dns = DNS(payload)
            # scapy parses almost anything (footgun): require a plausible DNS
            # header. Real DNS has a valid QR bit, an opcode in 0-5, sane
            # counts and AT LEAST one question or answer. Random non-DNS UDP
            # payloads sniffed on arbitrary ports otherwise get decoded as
            # bogus DNS with zero questions/answers and garbage opcode/rcode
            # (e.g. a broadcast whose nscount/arcount happened to be nonzero
            # let it past the old ``qdcount+ancount+nscount+arcount`` sum).
            if dns.qr not in (0, 1):
                return None
            if dns.opcode > 5:  # valid opcodes: QUERY=0 .. DSO=5
                return None
            if dns.qdcount > 100 or dns.ancount > 1000:
                return None
            # An authoritative response may echo zero questions, but unless
            # it carries at least one question OR answer it is not DNS.
            if dns.qdcount + dns.ancount == 0:
                return None
            return dns
        except Exception:
            return None

    def _iter_payloads(self, stream: TCPStream | UDPFlow):
        if isinstance(stream, UDPFlow):
            for pkt in stream.packets:
                yield pkt.payload, pkt.timestamp
        else:
            # DNS-over-TCP: each message carries a 2-byte length prefix and a
            # single message may span MULTIPLE TCP segments. Reassembling per
            # frame (old behaviour) decoded only the first segment of a
            # fragmented message. Rebuild the byte stream from all frames and
            # yield only complete messages; a trailing partial message is
            # re-yielded once its tail arrives (the engine dedups re-parses).
            buf = b""
            for f in stream.frames:
                buf += f.payload
                while len(buf) >= 2:
                    msg_len = int.from_bytes(buf[:2], "big")
                    if len(buf) < 2 + msg_len:
                        break
                    yield buf[2:2 + msg_len], f.timestamp
                    buf = buf[2 + msg_len:]

    def _first_dns(self, stream: TCPStream | UDPFlow):
        for payload, _ in self._iter_payloads(stream):
            dns = self._parse(payload)
            if dns is not None:
                return dns
        return None

    def decode(self, stream: TCPStream | UDPFlow, start: int = 0) -> Iterator[ProtocolFrame]:
        """Decode DNS messages in the stream.

        ``start`` is the ABSOLUTE number of flow packets already decoded
        (stream.trimmed + local index). The engine checkpoints it so each new
        packet only decodes the new payloads instead of re-parsing the whole
        flow on every datagram (O(n²) without it). The TCP path re-builds the
        byte stream and ignores ``start`` — DNS-over-TCP streams are rare and
        short.
        """
        if isinstance(stream, UDPFlow):
            local = max(0, start - stream.trimmed)
            payloads = ((p.payload, p.timestamp) for p in stream.packets[local:])
        else:
            payloads = self._iter_payloads(stream)
        for payload, ts in payloads:
            dns = self._parse(payload)
            if dns is None:
                continue
            questions = []
            try:
                for q in _as_list(dns.qd):
                    questions.append({
                        "name": _qname(q.qname),
                        "type": q.qtype,
                        "class": q.qclass,
                    })
            except Exception:
                pass
            answers = []
            try:
                for rr in _as_list(dns.an):
                    answers.append({
                        "name": _qname(rr.rrname),
                        "type": rr.type,
                        "ttl": rr.ttl,
                        "rdata": _rdata(rr),
                    })
            except Exception:
                pass
            yield ProtocolFrame(
                frame_type="dns",
                timestamp=ts,
                data={
                    "id": dns.id,
                    "is_query": dns.qr == 0,
                    "opcode": dns.opcode,
                    "rcode": dns.rcode,
                    "questions": questions,
                    "answers": answers,
                    "qdcount": dns.qdcount,
                    "ancount": dns.ancount,
                },
                raw_ref=payload,
                five_tuple=stream.five_tuple,
            )


class DHCPDecoder(ProtocolDecoder):
    """DHCP via scapy (BOOTP + DHCP options) — UDP ports 67/68."""

    name = "dhcp"
    ports = {67, 68}

    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        if not isinstance(stream, UDPFlow) or not stream.packets:
            return False
        return self._parse(stream.packets[0].payload) is not None

    def _parse(self, payload: bytes):
        try:
            from scapy.all import BOOTP
            if len(payload) < 236:  # BOOTP fixed header
                return None
            bootp = BOOTP(payload)
            if bootp.op not in (1, 2):
                return None
            return bootp
        except Exception:
            return None

    def decode(self, stream: TCPStream | UDPFlow, start: int = 0) -> Iterator[ProtocolFrame]:
        from scapy.all import DHCP
        if isinstance(stream, UDPFlow):
            local = max(0, start - stream.trimmed)
            packets = stream.packets[local:]
        else:
            packets = stream.packets
        for pkt in packets:
            bootp = self._parse(pkt.payload)
            if bootp is None:
                continue
            msg_type = None
            opts = {}
            try:
                # DHCP options start after the 236-byte BOOTP fixed header.
                dhcp = DHCP(pkt.payload[236:])
                for opt in dhcp.options:
                    # Entries are (name, value) tuples; 'end'/'pad' are bare.
                    if not isinstance(opt, tuple) or len(opt) < 2:
                        continue
                    name = opt[0]
                    if name == "message-type":
                        msg_type = opt[1]
                    elif name not in ("end", "pad"):
                        opts[name] = opt[1]
            except Exception:
                pass
            yield ProtocolFrame(
                frame_type="dhcp",
                timestamp=pkt.timestamp,
                data={
                    "op": bootp.op,
                    "is_request": bootp.op == 1,
                    "xid": bootp.xid,
                    "ciaddr": bootp.ciaddr,
                    "yiaddr": bootp.yiaddr,
                    "siaddr": bootp.siaddr,
                    "giaddr": bootp.giaddr,
                    "chaddr": bootp.chaddr.hex(),
                    "message_type": msg_type,
                    "options": opts,
                },
                raw_ref=pkt.payload,
                five_tuple=stream.five_tuple,
            )


class ARPDecoder(ProtocolDecoder):
    """ARP via scapy — packet-level (never appears in a TCP/UDP stream)."""

    name = "arp"
    ports = set()

    def can_decode(self, stream) -> bool:
        return False

    def decode(self, stream):
        return iter(())

    def can_decode_packet(self, pkt: RawPacket) -> bool:
        try:
            from scapy.all import ARP, Ether
            return ARP in Ether(pkt.raw_bytes)
        except Exception:
            return False

    def decode_packet(self, pkt: RawPacket) -> list[ProtocolFrame]:
        try:
            from scapy.all import ARP, Ether
            arp = Ether(pkt.raw_bytes)[ARP]
            return [ProtocolFrame(
                frame_type="arp",
                timestamp=pkt.timestamp,
                data={
                    "op": int(arp.op),
                    "is_request": int(arp.op) == 1,
                    "is_reply": int(arp.op) == 2,
                    "psrc": arp.psrc,
                    "pdst": arp.pdst,
                    "hwsrc": arp.hwsrc,
                    "hwdst": arp.hwdst,
                },
                raw_ref=pkt.raw_bytes,
            )]
        except Exception:
            return []


class ICMPDecoder(ProtocolDecoder):
    """ICMP via scapy — packet-level (never appears in a TCP/UDP stream)."""

    name = "icmp"
    ports = set()

    def can_decode(self, stream) -> bool:
        return False

    def decode(self, stream):
        return iter(())

    def can_decode_packet(self, pkt: RawPacket) -> bool:
        try:
            from scapy.all import Ether, ICMP, IP
            return ICMP in Ether(pkt.raw_bytes)
        except Exception:
            return False

    def decode_packet(self, pkt: RawPacket) -> list[ProtocolFrame]:
        try:
            from scapy.all import Ether, ICMP, IP
            eth = Ether(pkt.raw_bytes)
            icmp = eth[ICMP]
            data = {"type": int(icmp.type), "code": int(icmp.code)}
            if icmp.type in (0, 8) and hasattr(icmp, "id"):
                data["id"] = icmp.id
                data["seq"] = icmp.seq
            return [ProtocolFrame(
                frame_type="icmp",
                timestamp=pkt.timestamp,
                data=data,
                raw_ref=pkt.raw_bytes,
            )]
        except Exception:
            return []


__all__ = ["DNSDecoder", "DHCPDecoder", "ARPDecoder", "ICMPDecoder"]
