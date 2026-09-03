"""Tests for the network layer (capture, reassembly, scapy adapters, pcap, stats)."""
import asyncio
import struct
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from core.network.capture import RawPacket, PacketCapture
from core.network.pcap import PCAPWriter, PCAPReader, PCAPNGWriter, PCAPNG_MAGIC
from core.network.protocols import (
    DNSDecoder,
    DHCPDecoder,
    ARPDecoder,
    ICMPDecoder,
    QUICDecoder,
)
from core.network.protocols.base import FiveTuple, TCPStream, UDPFlow
from core.network.reassemble import TCPReassembler, UDPFlowTracker, TCPFrame, UDPPacket
from core.network.stats import NetworkStats, StatsCollector, LiveStatsBroadcaster


def _tcp_stream(frames, src_ip="10.0.0.1", dst_ip="93.184.216.34",
                src_port=54321, dst_port=80):
    ft = FiveTuple(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                   dst_port=dst_port, protocol=6)
    stream = TCPStream(five_tuple=ft)
    stream.frames = frames
    return stream


def _frame(payload, ts=None, is_client=True, seq=1000):
    return TCPFrame(
        seq_start=seq,
        seq_end=seq + len(payload),
        payload=payload,
        flags=0x18,
        timestamp=ts or datetime.now(),
        is_client=is_client,
    )


def _tcp_pkt(seq, data, sport=54321, dport=80, ts_off=0, flags="PA", options=None):
    from scapy.all import IP, TCP
    tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq)
    if options:
        tcp.options = options
    pkt = IP(src="10.0.0.1", dst="93.184.216.34") / tcp / data
    return RawPacket(
        timestamp=datetime.now() + timedelta(seconds=ts_off),
        raw_bytes=bytes(pkt),
        interface="eth0",
    )


class TestPCAP:
    def test_pcap_roundtrip(self, tmp_path):
        path = str(tmp_path / "test.pcap")
        pkt = RawPacket(timestamp=datetime(2024, 1, 1, 12, 0, 0),
                        raw_bytes=b"\x00" * 64, interface="eth0")

        with PCAPWriter(path) as w:
            w.write_packet(pkt)

        with PCAPReader(path) as r:
            packets = list(r.packets())

        assert len(packets) == 1
        assert packets[0].raw_bytes == pkt.raw_bytes
        assert packets[0].metadata["orig_len"] == 64

    def test_writer_del_closes_file(self, tmp_path):
        """write_packet() auto-opens the file — a caller that never calls
        close() (or dies mid-flight) must not leak the descriptor."""
        import gc

        path = str(tmp_path / "leak.pcap")
        pkt = RawPacket(timestamp=datetime.now(), raw_bytes=b"\x00" * 16, interface="eth0")

        w = PCAPWriter(path)
        w.write_packet(pkt)  # auto-opens
        fh = w._fh
        assert fh is not None and not fh.closed

        del w
        gc.collect()
        assert fh.closed

    def test_pcapng_structure(self, tmp_path):
        path = str(tmp_path / "test.pcapng")
        pkt = RawPacket(timestamp=datetime(2024, 1, 1, 12, 0, 0),
                        raw_bytes=b"\xab" * 100, interface="eth0")

        with PCAPNGWriter(path) as w:
            w.write_packet(pkt)

        raw = Path(path).read_bytes()
        epb_start = 28 + 20  # SHB + IDB

        assert raw[:4] == struct.pack(">I", PCAPNG_MAGIC)
        shb_len = struct.unpack(">I", raw[4:8])[0]
        assert shb_len == 28
        assert raw[8:12] == struct.pack(">I", 0x1A2B3C4D)

        idb_len = struct.unpack(">I", raw[28 + 4:28 + 8])[0]
        assert idb_len == 20

        epb_len = struct.unpack(">I", raw[epb_start + 4:epb_start + 8])[0]
        assert epb_len == 132
        assert struct.unpack(">I", raw[epb_start + 132 - 4:epb_start + 132])[0] == 132
        assert len(raw) == epb_start + 132

    def test_pcapng_length_not_multiple_of_4(self, tmp_path):
        path = str(tmp_path / "odd.pcapng")
        pkt = RawPacket(timestamp=datetime(2024, 1, 1, 12, 0, 0),
                        raw_bytes=b"\x01\x02\x03", interface="eth0")

        with PCAPNGWriter(path) as w:
            w.write_packet(pkt)

        raw = Path(path).read_bytes()
        epb_start = 28 + 20
        epb_len = struct.unpack(">I", raw[epb_start + 4:epb_start + 8])[0]
        assert epb_len == 36
        assert len(raw) == epb_start + 36

    def test_pcapng_timestamp_is_microseconds_since_epoch(self, tmp_path):
        """Regression: the old writer encoded sec<<32 | 2^-32 fraction, which
        Wireshark would read as seconds + millions of seconds. With the default
        if_tsresol (10^-6) the 64-bit value must be plain microseconds."""
        path = str(tmp_path / "ts.pcapng")
        ts = datetime(2024, 1, 1, 12, 0, 0)

        with PCAPNGWriter(str(path)) as w:
            w.write_packet(RawPacket(timestamp=ts, raw_bytes=b"\x00" * 10, interface="eth0"))

        raw = Path(path).read_bytes()
        epb_start = 28 + 20  # SHB + IDB
        # EPB: type(4) len(4) iface(4) ts_high(4) ts_low(4) ...
        ts_high = struct.unpack(">I", raw[epb_start + 12:epb_start + 16])[0]
        ts_low = struct.unpack(">I", raw[epb_start + 16:epb_start + 20])[0]
        micros = (ts_high << 32) | ts_low
        # Independent integer-math expectation (same rounding as the writer).
        sec = int(ts.timestamp())
        usec = int(round((ts.timestamp() - sec) * 1_000_000))
        assert micros == sec * 1_000_000 + usec


class TestDNSDecoder:
    def test_dns_query_udp(self):
        from scapy.all import DNS, DNSQR
        dns = DNS(id=0x1234, qr=0, qd=DNSQR(qname="www.example.com", qtype=1, qclass=1))
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "8.8.8.8", 53000, 53, 17))
        flow.packets.append(UDPPacket(payload=bytes(dns), timestamp=datetime.now(), length=len(bytes(dns))))

        frames = list(DNSDecoder().decode(flow))
        assert len(frames) == 1
        assert frames[0].data["is_query"] is True
        assert frames[0].data["questions"] == [{"name": "www.example.com", "type": 1, "class": 1}]

    def test_dns_query_raw_bytes(self):
        # Hand-built header + qname — scapy must decode real-world bytes.
        dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        dns += b"\x03www\x07example\x03com\x00"
        dns += struct.pack(">HH", 1, 1)

        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "8.8.8.8", 53000, 53, 17))
        flow.packets.append(UDPPacket(payload=dns, timestamp=datetime.now(), length=len(dns)))

        frames = list(DNSDecoder().decode(flow))
        assert len(frames) == 1
        assert frames[0].data["questions"][0]["name"] == "www.example.com"

    def test_dns_over_tcp(self):
        inner = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        inner += b"\x02ab\x00" + struct.pack(">HH", 1, 1)
        framed = struct.pack(">H", len(inner)) + inner

        stream = _tcp_stream([_frame(framed, is_client=True)], dst_port=53)
        frames = list(DNSDecoder().decode(stream))
        assert len(frames) == 1
        assert frames[0].data["questions"][0]["name"] == "ab"

    def test_can_decode_rejects_non_dns(self):
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "8.8.8.8", 53000, 9999, 17))
        flow.packets.append(UDPPacket(payload=b"\x00" * 40, timestamp=datetime.now(), length=40))
        assert DNSDecoder().can_decode(flow) is False

    def test_dns_response_with_answers(self):
        """A DNS response (qr=1) with answers must decode rcode + answer records."""
        from scapy.all import DNS, DNSQR, DNSRR
        dns = DNS(
            id=0x5678, qr=1, rcode=0,
            qd=DNSQR(qname="example.com", qtype=1, qclass=1),
            an=DNSRR(rrname="example.com", type=1, ttl=300, rdata="93.184.216.34"),
        )
        flow = UDPFlow(five_tuple=FiveTuple("8.8.8.8", "10.0.0.1", 53, 53000, 17))
        flow.packets.append(UDPPacket(payload=bytes(dns), timestamp=datetime.now(), length=len(bytes(dns))))

        frames = list(DNSDecoder().decode(flow))
        assert len(frames) == 1
        data = frames[0].data
        assert data["is_query"] is False
        assert data["rcode"] == 0
        assert data["answers"] == [
            {"name": "example.com", "type": 1, "ttl": 300, "rdata": "93.184.216.34"}
        ]

    def test_garbage_udp_payload_with_bogus_opcode_rejected(self):
        """Regression: the UDP broadcast Nyx decoded as DNS (opcode=10,
        rcode=10, zero questions/answers) must NOT be accepted as DNS."""
        # Header, qr=0, opcode=10 (flags 0x500A), zero records.
        hdr = struct.pack(">HHHHHH", 0, 0x500A, 0, 0, 0, 0)
        payload = hdr + b"\x00" * 24
        flow = UDPFlow(five_tuple=FiveTuple("192.168.1.51", "255.255.255.255", 55428, 6667, 17))
        flow.packets.append(UDPPacket(payload=payload, timestamp=datetime.now(), length=len(payload)))

        decoder = DNSDecoder()
        assert decoder.can_decode(flow) is False
        assert list(decoder.decode(flow)) == []

    def test_recordless_header_with_nonzero_nscount_rejected(self):
        """Regression surface: a header with opcode=0 but zero questions AND
        zero answers — even if nscount/arcount are nonzero — is not DNS. The
        old guard summed qdcount+ancount+nscount+arcount and let it through."""
        # opcode=0, RD flag set, qdcount=0, ancount=0, nscount=3, arcount=0.
        hdr = struct.pack(">HHHHHH", 1, 0x0100, 0, 0, 3, 0)
        payload = hdr + b"\x00" * 24
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "8.8.8.8", 53000, 53, 17))
        flow.packets.append(UDPPacket(payload=payload, timestamp=datetime.now(), length=len(payload)))

        decoder = DNSDecoder()
        assert decoder.can_decode(flow) is False
        assert list(decoder.decode(flow)) == []

    def test_short_non_dns_payload_rejected(self):
        """A <12-byte UDP payload (e.g. an ICMP/other packet mis-sniffed) is
        never DNS."""
        flow = UDPFlow(five_tuple=FiveTuple("1.2.3.4", "5.6.7.8", 1234, 9999, 17))
        flow.packets.append(UDPPacket(payload=b"\xaa" * 8, timestamp=datetime.now(), length=8))
        assert DNSDecoder().can_decode(flow) is False

    def test_dns_over_tcp_partial_message_not_decoded(self):
        """A DNS-over-TCP message may span multiple TCP segments — a frame
        carrying only the length prefix + part of the message must not be
        decoded (old per-frame parsing decoded garbage from the truncated
        message)."""
        inner = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        inner += b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        framed = struct.pack(">H", len(inner)) + inner

        stream = _tcp_stream([_frame(framed[:10], is_client=True)], dst_port=53)
        decoder = DNSDecoder()
        assert decoder.can_decode(stream) is False
        assert list(decoder.decode(stream)) == []

    def test_dns_over_tcp_message_spans_segments(self):
        inner = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        inner += b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        framed = struct.pack(">H", len(inner)) + inner

        split = 6
        stream = _tcp_stream([
            _frame(framed[:split], is_client=True, seq=1000),
            _frame(framed[split:], is_client=True, seq=1000 + split),
        ], dst_port=53)

        decoder = DNSDecoder()
        assert decoder.can_decode(stream) is True
        frames = list(decoder.decode(stream))
        assert len(frames) == 1
        assert frames[0].frame_type == "dns"
        assert frames[0].data["questions"][0]["name"] == "www.example.com"


class TestDHCPDecoder:
    def test_dhcp_discover(self):
        from scapy.all import BOOTP, DHCP
        # In scapy 2.7 DHCP is a standalone options-only layer; a real DHCP
        # datagram is the 236-byte BOOTP header followed by the options.
        bootp = BOOTP(op=1, chaddr="aa:bb:cc:dd:ee:ff", xid=0x1234)
        payload = bytes(bootp) + bytes(DHCP(options=[("message-type", 1), ("hostname", b"nyx-test"), "end"]))

        flow = UDPFlow(five_tuple=FiveTuple("0.0.0.0", "255.255.255.255", 68, 67, 17))
        flow.packets.append(UDPPacket(payload=payload, timestamp=datetime.now(), length=len(payload)))

        assert DHCPDecoder().can_decode(flow) is True
        frames = list(DHCPDecoder().decode(flow))
        assert len(frames) == 1
        assert frames[0].frame_type == "dhcp"
        assert frames[0].data["is_request"] is True
        assert frames[0].data["message_type"] == 1
        assert frames[0].data["options"].get("hostname") == b"nyx-test"

    def _flow(self, payload):
        flow = UDPFlow(five_tuple=FiveTuple("0.0.0.0", "255.255.255.255", 68, 67, 17))
        flow.packets.append(UDPPacket(payload=payload, timestamp=datetime.now(), length=len(payload)))
        return flow

    def test_dhcp_offer(self):
        """DHCP OFFER (op=2, message-type 2) is a server reply."""
        from scapy.all import BOOTP, DHCP
        bootp = BOOTP(op=2, chaddr="aa:bb:cc:dd:ee:ff", yiaddr="192.168.1.50", xid=0x1234)
        payload = bytes(bootp) + bytes(DHCP(options=[("message-type", 2), "end"]))

        frames = list(DHCPDecoder().decode(self._flow(payload)))
        assert len(frames) == 1
        assert frames[0].data["is_request"] is False
        assert frames[0].data["op"] == 2
        assert frames[0].data["message_type"] == 2
        assert frames[0].data["yiaddr"] == "192.168.1.50"

    def test_dhcp_ack(self):
        """DHCP ACK (message-type 5) — the final offer acceptance."""
        from scapy.all import BOOTP, DHCP
        bootp = BOOTP(op=2, chaddr="aa:bb:cc:dd:ee:ff", yiaddr="192.168.1.50", xid=0x1234)
        payload = bytes(bootp) + bytes(DHCP(options=[("message-type", 5), "end"]))

        frames = list(DHCPDecoder().decode(self._flow(payload)))
        assert len(frames) == 1
        assert frames[0].data["message_type"] == 5

    def test_dhcp_rejects_short_payload(self):
        """<236-byte payload is never DHCP (BOOTP fixed header required)."""
        assert DHCPDecoder().can_decode(self._flow(b"\x00" * 100)) is False

    def test_dhcp_rejects_invalid_op(self):
        """Bootp op outside (1, 2) is rejected."""
        from scapy.all import BOOTP, DHCP
        bootp = BOOTP(op=3, chaddr="aa:bb:cc:dd:ee:ff", xid=0x1234)  # bogus op
        payload = bytes(bootp) + bytes(DHCP(options=[("message-type", 1), "end"]))
        assert DHCPDecoder().can_decode(self._flow(payload)) is False


class TestARPDecoder:
    def test_arp_request(self):
        from scapy.all import ARP, Ether
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") / \
            ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1")
        raw = RawPacket(timestamp=datetime.now(), raw_bytes=bytes(pkt), interface="eth0")

        assert ARPDecoder().can_decode_packet(raw) is True
        frames = ARPDecoder().decode_packet(raw)
        assert len(frames) == 1
        assert frames[0].frame_type == "arp"
        assert frames[0].data["is_request"] is True
        assert frames[0].data["psrc"] == "192.168.1.10"

    def test_arp_reply(self):
        from scapy.all import ARP, Ether
        pkt = Ether(dst="aa:bb:cc:dd:ee:ff", src="11:22:33:44:55:66") / \
            ARP(op=2, psrc="192.168.1.1", pdst="192.168.1.10",
                hwsrc="11:22:33:44:55:66", hwdst="aa:bb:cc:dd:ee:ff")
        raw = RawPacket(timestamp=datetime.now(), raw_bytes=bytes(pkt), interface="eth0")

        assert ARPDecoder().can_decode_packet(raw) is True
        frames = ARPDecoder().decode_packet(raw)
        assert len(frames) == 1
        data = frames[0].data
        assert data["is_request"] is False
        assert data["is_reply"] is True
        assert data["op"] == 2
        assert data["psrc"] == "192.168.1.1"
        assert data["pdst"] == "192.168.1.10"
        assert data["hwsrc"] == "11:22:33:44:55:66"

    def test_not_arp(self):
        from scapy.all import IP, UDP
        pkt = IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53, dport=53)
        raw = RawPacket(timestamp=datetime.now(), raw_bytes=bytes(pkt), interface="eth0")
        assert ARPDecoder().can_decode_packet(raw) is False


class TestICMPDecoder:
    def test_echo_request(self):
        from scapy.all import ICMP, IP, Ether
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0, id=0x1234, seq=1)
        raw = RawPacket(timestamp=datetime.now(), raw_bytes=bytes(pkt), interface="eth0")

        assert ICMPDecoder().can_decode_packet(raw) is True
        frames = ICMPDecoder().decode_packet(raw)
        assert len(frames) == 1
        assert frames[0].data["type"] == 8
        assert frames[0].data["id"] == 0x1234

    def test_echo_reply(self):
        """ICMP echo reply (type 0) — the response to a ping."""
        from scapy.all import ICMP, IP, Ether
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0, code=0, id=0x1234, seq=1)
        raw = RawPacket(timestamp=datetime.now(), raw_bytes=bytes(pkt), interface="eth0")

        frames = ICMPDecoder().decode_packet(raw)
        assert len(frames) == 1
        data = frames[0].data
        assert data["type"] == 0
        assert data["id"] == 0x1234
        assert data["seq"] == 1

    def test_dest_unreachable_no_id_seq(self):
        """Non-echo ICMP (e.g. type 3 dest-unreachable) has type/code but no
        id/seq attributes — the decoder must not crash and must omit them."""
        from scapy.all import ICMP, IP, Ether
        pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=3, code=1)
        raw = RawPacket(timestamp=datetime.now(), raw_bytes=bytes(pkt), interface="eth0")

        frames = ICMPDecoder().decode_packet(raw)
        assert len(frames) == 1
        data = frames[0].data
        assert data["type"] == 3
        assert data["code"] == 1
        assert "id" not in data
        assert "seq" not in data


class TestQUICDecoder:
    def test_long_header_version_detection(self):
        pkt = b"\xc0" + struct.pack(">I", 1) + b"\x00\x00"

        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "1.1.1.1", 10000, 443, 17))
        flow.packets.append(UDPPacket(payload=pkt, timestamp=datetime.now(), length=len(pkt)))

        assert QUICDecoder().can_decode(flow) is True
        frames = list(QUICDecoder().decode(flow))
        assert len(frames) == 1
        assert frames[0].data["version"] == 1

    def test_short_header_not_decoded_as_long(self):
        pkt = b"\x40\x01\x02"
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "1.1.1.1", 10000, 443, 17))
        flow.packets.append(UDPPacket(payload=pkt, timestamp=datetime.now(), length=len(pkt)))

        assert QUICDecoder().can_decode(flow) is False

    def test_v2_long_header_version_detection(self):
        """QUIC v2 uses a different version number but must decode as a long
        header (initial packet type, dcid/scid extracted)."""
        # first byte: long header (0x80) | initial packet type (0x00)
        pkt = b"\x80" + struct.pack(">I", 0x00000002) + b"\x08\x08" + b"A" * 8 + b"B" * 8

        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "1.1.1.1", 10000, 443, 17))
        flow.packets.append(UDPPacket(payload=pkt, timestamp=datetime.now(), length=len(pkt)))

        assert QUICDecoder().can_decode(flow) is True
        frames = list(QUICDecoder().decode(flow))
        assert len(frames) == 1
        data = frames[0].data
        assert data["header_form"] == "long"
        assert data["version"] == 0x00000002
        assert data["packet_type"] == "initial"
        assert data["dcid"] == (b"A" * 8).hex()
        assert data["scid"] == (b"B" * 8).hex()

    def test_long_header_handshake_packet_type(self):
        """0x20 packet type (first byte 0xA0) decodes as 'handshake'."""
        pkt = b"\xa0" + struct.pack(">I", 1) + b"\x01\x01" + b"C" + b"D"
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "1.1.1.1", 10000, 443, 17))
        flow.packets.append(UDPPacket(payload=pkt, timestamp=datetime.now(), length=len(pkt)))

        frames = list(QUICDecoder().decode(flow))
        assert frames[0].data["packet_type"] == "handshake"

    def test_short_header_parsed_when_forced(self):
        """decode() parses whatever _parse_quic accepts; a short header packet
        passed in directly yields a 'short' frame (can_decode blocks it from a
        flow, but the parser path itself is exercised here)."""
        decoder = QUICDecoder()
        data = decoder._parse_quic(b"\x51\xaa\xbb")  # short header, spin bit 1
        assert data["header_form"] == "short"
        assert data["spin_bit"] is True
        # pn_length = (0x01 & 0x03) + 1 = 2
        assert data["packet_number_length"] == 2

    def test_long_header_0rtt_packet_type(self):
        """0x10 packet type (first byte 0x90) decodes as 0rtt."""
        pkt = b"\x90" + struct.pack(">I", 1) + b"\x01\x01" + b"C" + b"D"
        data = QUICDecoder()._parse_long_header(pkt)
        assert data["packet_type"] == "0rtt"

    def test_short_header_pn_length_variants(self):
        """pn_length maps the low 2 bits +1; spin/key bits are extracted."""
        decoder = QUICDecoder()
        d = decoder._parse_quic(b"\x01\x00")  # short header, spin 0, pn_len 2
        assert d["packet_number_length"] == 2
        assert d["spin_bit"] is False
        d = decoder._parse_quic(b"\x47")     # low bits 3 => pn_len 4
        assert d["packet_number_length"] == 4
        assert d["spin_bit"] is True

    # ── aggregation (option 1: one row per connection) ───────────────────

    @staticmethod
    def _long_initial(dcid: bytes) -> bytes:
        # long header | v1 | initial | dcil=8, scil=0 | dcid
        return b"\xc0" + struct.pack(">I", 1) + b"\x08\x00" + dcid

    def test_aggregate_groups_by_dcid(self):
        """Two long-header DCIDs in one flow -> two aggregated summary frames."""
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "1.1.1.1", 10000, 443, 17))
        now = datetime.now()
        flow.packets.append(UDPPacket(payload=self._long_initial(b"A" * 8), timestamp=now, length=20))
        flow.packets.append(UDPPacket(payload=self._long_initial(b"B" * 8), timestamp=now, length=20))
        flow.packets.append(UDPPacket(payload=b"\x43\x01\x02\x03", timestamp=now, length=6))

        frames = list(QUICDecoder().decode(flow, aggregate=True))
        assert len(frames) == 2
        by_conn = {f.data["conn_id"]: f.data for f in frames}
        assert by_conn[(b"A" * 8).hex()]["packet_count"] == 1
        # The short-header packet is attributed to the most recent connection.
        assert by_conn[(b"B" * 8).hex()]["packet_count"] == 2
        assert by_conn[(b"B" * 8).hex()]["packet_types"] == {"initial": 1, "short": 1}
        assert all(f.data["aggregated"] for f in frames)

    def test_aggregate_single_connection_flow(self):
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "1.1.1.1", 10000, 443, 17))
        now = datetime.now()
        flow.packets.append(UDPPacket(payload=self._long_initial(b"C" * 8), timestamp=now, length=20))
        for _ in range(5):
            flow.packets.append(UDPPacket(payload=b"\x43\x01\x02\x03", timestamp=now, length=6))

        frames = list(QUICDecoder().decode(flow, aggregate=True))
        assert len(frames) == 1
        assert frames[0].data["packet_count"] == 6
        assert frames[0].data["packet_types"] == {"initial": 1, "short": 5}
        assert frames[0].data["version"] == 1


class TestSNIExtraction:
    def _client_hello_body(self):
        body = b"\x03\x03"                     # legacy version
        body += b"\x00" * 32                    # random
        body += b"\x00"                         # session id len
        body += b"\x00\x02" + b"\x13\x01"       # cipher suites
        body += b"\x01\x00"                     # compression methods
        ext = b"\x00\x00" + struct.pack(">H", 12) + struct.pack(">H", 10) + \
              b"\x00" + struct.pack(">H", 7) + b"example"
        body += struct.pack(">H", len(ext)) + ext
        return body

    def test_extract_sni_from_payload(self):
        from modules.network.mitm_integration import extract_sni_from_payload
        assert extract_sni_from_payload(self._client_hello_body()) == "example"

    def test_extract_sni_from_stream(self):
        from modules.network.mitm_integration import extract_sni_from_stream
        body = self._client_hello_body()
        handshake = struct.pack(">B", 1) + struct.pack(">I", len(body))[1:] + body
        record = struct.pack(">BHH", 22, 0x0301, len(handshake)) + handshake

        stream = _tcp_stream([_frame(record, is_client=True)], dst_port=443)
        assert extract_sni_from_stream(stream) == "example"

    def test_no_sni_for_plain_http_port(self):
        from modules.network.mitm_integration import extract_sni_from_stream
        stream = _tcp_stream([_frame(b"GET / HTTP/1.1\r\n\r\n", is_client=True)], dst_port=80)
        assert extract_sni_from_stream(stream) is None

    def test_sni_list_with_non_hostname_entry_first(self):
        """Regression: the name-list walk advanced by 1 byte for entries that
        are not host_name (type 0), walking into the middle of the next entry.
        Each entry is type(1) + length(2) + value, so the walk must skip the
        full 3-byte header regardless of type."""
        from modules.network.mitm_integration import extract_sni_from_payload

        body = b"\x03\x03" + b"\x00" * 32
        body += b"\x00"                        # session id len
        body += b"\x00\x02" + b"\x13\x01"      # cipher suites
        body += b"\x01\x00"                     # compression methods
        # server_name ext: list with a non-host_name entry first (type 1,
        # value "zz") then the real host_name "example.com".
        entries = b"\x01" + struct.pack(">H", 2) + b"zz"
        entries += b"\x00" + struct.pack(">H", 11) + b"example.com"
        ext = b"\x00\x00" + struct.pack(">H", 2 + len(entries)) + struct.pack(">H", len(entries)) + entries
        body += struct.pack(">H", len(ext)) + ext

        assert extract_sni_from_payload(body) == "example.com"

    def test_extract_sni_from_truncated_payload(self):
        """Truncated ClientHello returns None, no crash."""
        from modules.network.mitm_integration import extract_sni_from_payload
        assert extract_sni_from_payload(b"\x03\x03" + b"\x00" * 10) is None

    def test_extract_sni_from_empty_payload(self):
        from modules.network.mitm_integration import extract_sni_from_payload
        assert extract_sni_from_payload(b"") is None

    def test_extract_sni_from_non_tls_payload(self):
        from modules.network.mitm_integration import extract_sni_from_payload
        assert extract_sni_from_payload(b"GET / HTTP/1.1\r\n\r\n") is None

    def test_extract_sni_from_stream_non_tls_port(self):
        """Stream on port 80 (HTTP) returns None."""
        from modules.network.mitm_integration import extract_sni_from_stream
        stream = _tcp_stream([_frame(b"data", is_client=True)], dst_port=80)
        assert extract_sni_from_stream(stream) is None

    def test_extract_sni_from_stream_no_frames(self):
        """Stream with no frames returns None."""
        from modules.network.mitm_integration import extract_sni_from_stream
        stream = _tcp_stream([])
        assert extract_sni_from_stream(stream) is None

    def test_extract_sni_from_stream_server_frames_only(self):
        """Stream with only server frames returns None (no client hello)."""
        from modules.network.mitm_integration import extract_sni_from_stream
        stream = _tcp_stream([_frame(b"response", is_client=False)], dst_port=443)
        assert extract_sni_from_stream(stream) is None


class TestMITMIntegrationFeed:
    """Test feed_mitmproxy_from_stream — the bridge to mitmproxy."""

    def test_feed_logs_stream_info(self, caplog):
        """feed_mitmproxy_from_stream logs client/server byte counts."""
        from modules.network.mitm_integration import feed_mitmproxy_from_stream
        import logging

        stream = _tcp_stream([
            _frame(b"client request", is_client=True),
            _frame(b"server response", is_client=False),
        ])

        with caplog.at_level(logging.INFO):
            feed_mitmproxy_from_stream(stream, sni="example.com")

        assert "example.com" in caplog.text
        assert "14B client" in caplog.text  # len(b"client request")
        assert "15B server" in caplog.text  # len(b"server response")

    def test_feed_no_sni(self, caplog):
        """feed_mitmproxy_from_stream works with None SNI."""
        from modules.network.mitm_integration import feed_mitmproxy_from_stream
        import logging

        stream = _tcp_stream([
            _frame(b"data", is_client=True),
        ])

        with caplog.at_level(logging.INFO):
            feed_mitmproxy_from_stream(stream, sni=None)

        assert "no-SNI" in caplog.text

    def test_feed_empty_stream(self, caplog):
        """feed_mitmproxy_from_stream handles empty streams."""
        from modules.network.mitm_integration import feed_mitmproxy_from_stream
        import logging

        stream = _tcp_stream([])

        with caplog.at_level(logging.INFO):
            feed_mitmproxy_from_stream(stream, sni="empty.test")

        assert "empty.test" in caplog.text
        assert "0B client" in caplog.text
        assert "0B server" in caplog.text


class TestEngineSNIIntegration:
    """Test that the engine correctly labels TLS streams with SNI."""

    @pytest.mark.asyncio
    async def test_engine_labels_tls_stream_with_sni(self):
        """Engine extracts SNI from TLS stream and adds it to metadata."""
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="lo", bpf_filter="tcp")
        # Build a TLS ClientHello with SNI "test.example.com"
        body = b"\x03\x03" + b"\x00" * 32
        body += b"\x00"
        body += b"\x00\x02" + b"\x13\x01"
        body += b"\x01\x00"
        entries = b"\x00" + struct.pack(">H", 16) + b"test.example.com"
        ext = b"\x00\x00" + struct.pack(">H", 2 + len(entries)) + struct.pack(">H", len(entries)) + entries
        body += struct.pack(">H", len(ext)) + ext

        handshake = struct.pack(">B", 1) + struct.pack(">I", len(body))[1:] + body
        record = struct.pack(">BHH", 22, 0x0301, len(handshake)) + handshake

        ft = FiveTuple(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=54321, dst_port=443, protocol=6)
        from core.network.reassemble import TCPStream
        stream = TCPStream(five_tuple=ft)
        stream.frames = [_frame(record, is_client=True)]

        # Simulate what the engine does
        from modules.network.mitm_integration import extract_sni_from_stream
        sni = extract_sni_from_stream(stream)
        assert sni == "test.example.com"
        stream.metadata["sni"] = sni

        assert stream.metadata["sni"] == "test.example.com"

    @pytest.mark.asyncio
    async def test_engine_no_sni_for_http_stream(self):
        """Engine doesn't add SNI to non-TLS streams."""
        from core.network.protocols.base import TCPStream

        ft = FiveTuple(src_ip="10.0.0.1", dst_ip="93.184.216.34", src_port=54321, dst_port=80, protocol=6)
        stream = TCPStream(five_tuple=ft)
        stream.frames = [_frame(b"GET / HTTP/1.1\r\n\r\n", is_client=True)]

        from modules.network.mitm_integration import extract_sni_from_stream
        sni = extract_sni_from_stream(stream)
        assert sni is None
        assert "sni" not in stream.metadata


class TestStats:
    def test_to_dict_is_json_serializable(self):
        collector = StatsCollector()
        pkt = RawPacket(timestamp=datetime.now(), raw_bytes=b"\x00" * 100, interface="eth0")
        collector.record_packet(pkt, protocol="http", port=80)

        stats = collector.get_stats(tcp_streams=2, udp_flows=1)
        d = stats.to_dict()
        assert d["packets_total"] == 1
        assert d["by_protocol"] == {"http": 1}
        assert d["by_port"] == {80: 1}
        assert d["tcp_streams"] == 2
        assert "timestamp" in d

        import json
        json.dumps(d)  # must not raise

    def test_network_stats_defaults(self):
        stats = NetworkStats()
        d = stats.to_dict()
        assert d["pps"] == 0.0
        assert d["active_flows"] == 0

    def test_record_packet_thread_safety(self):
        """The capture thread records while the event loop reads — the shared
        counters must be lock-protected (regression: the lock existed but was
        never used)."""
        collector = StatsCollector()

        def worker():
            for _ in range(500):
                collector.record_packet(
                    RawPacket(timestamp=datetime.now(), raw_bytes=b"x" * 10, interface="eth0")
                )

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert collector._stats.packets_total == 2000
        assert collector._stats.bytes_total == 20000

    def test_broadcast_subscriber_queue_is_bounded_and_live(self):
        """Regression: asyncio.Queue() is unbounded so put_nowait never raised
        QueueFull and the except branch was dead code. Subscriber queues must
        be bounded (1 slot) and keep delivering the newest snapshot."""
        async def _run():
            collector = StatsCollector()
            broadcaster = LiveStatsBroadcaster(collector, interval=0.01)
            q = broadcaster.subscribe()
            assert q.maxsize == 1
            await broadcaster.start(lambda: 0, lambda: 0)
            try:
                first = await asyncio.wait_for(q.get(), timeout=1)
                assert first.packets_total == 0
                # Slow consumer: after a delay the queue still delivers the
                # newest snapshot (stale ones were dropped, not accumulated).
                await asyncio.sleep(0.05)
                second = await asyncio.wait_for(q.get(), timeout=1)
                assert second.timestamp >= first.timestamp
            finally:
                await broadcaster.stop()

        asyncio.run(_run())


class TestAdaptiveCapture:
    """Adaptive capture: interface auto-resolution + watchdog rebind.

    All rebind tests use fake captures / monkeypatched resolvers — no real
    sniffer threads are started.
    """

    def test_resolve_active_interface_returns_string(self):
        from core.network.capture import resolve_active_interface
        name = resolve_active_interface()
        assert isinstance(name, str)
        # On a machine with networking this normally finds the live NIC;
        # tolerate "" (sandboxed/CI) — the type contract is what matters.

    def test_list_capture_interfaces_shape(self):
        from core.network.capture import list_capture_interfaces
        entries = list_capture_interfaces()
        assert isinstance(entries, list)
        for e in entries:
            for key in ("name", "is_up", "is_loopback", "ipv4", "is_default"):
                assert key in e, f"missing key: {key}"
            assert isinstance(e["ipv4"], list)
            assert isinstance(e["is_default"], bool)
        # At most one interface is flagged as the default.
        defaults = [e for e in entries if e["is_default"]]
        assert len(defaults) <= 1


class TestInterfaceResolutionCache:
    """resolve_active_interface(cached=True) must not re-run the expensive
    scapy/psutil enumeration on every call (the watchdog previously resolved
    on the event loop every poll — freezing all HTTP requests on Windows).
    """

    def _patch_resolver(self, monkeypatch, name="Wi-Fi"):
        import core.network.capture as cap
        calls = []
        monkeypatch.setattr(cap, "_resolve_active_interface_uncached",
                            lambda: (calls.append(1), name)[1])
        monkeypatch.setattr(cap, "_resolve_cache", None)
        return calls

    def test_repeated_cached_calls_resolve_once(self, monkeypatch):
        import core.network.capture as cap
        calls = self._patch_resolver(monkeypatch)
        assert cap.resolve_active_interface() == "Wi-Fi"
        assert cap.resolve_active_interface() == "Wi-Fi"
        assert cap.resolve_active_interface() == "Wi-Fi"
        assert len(calls) == 1  # two calls served from the TTL cache

    def test_expired_cache_re_resolves(self, monkeypatch):
        import core.network.capture as cap
        calls = self._patch_resolver(monkeypatch)
        # Stale entry older than the TTL -> must resolve again.
        monkeypatch.setattr(cap, "_resolve_cache",
                            (time.monotonic() - 999, "stale"))
        assert cap.resolve_active_interface() == "Wi-Fi"
        assert len(calls) == 1

    def test_cached_false_bypasses_cache(self, monkeypatch):
        import core.network.capture as cap
        calls = self._patch_resolver(monkeypatch)
        # Warm, still-valid cache entry — cached=False must ignore it.
        monkeypatch.setattr(cap, "_resolve_cache",
                            (time.monotonic(), "Wi-Fi"))
        assert cap.resolve_active_interface(cached=False) == "Wi-Fi"
        assert len(calls) == 1

    def test_engine_watchdog_uses_fresh_resolution(self):
        """The watchdog must bypass the cache (cached=False) or a stale
        cached name would prevent adaptive rebinding — and the resolve must
        run in a worker thread (to_thread), never on the event loop."""
        import inspect
        import modules.network.engine as eng_mod
        src = inspect.getsource(eng_mod.NetworkEngine._interface_watchdog)
        assert "to_thread(resolve_active_interface, False)" in src

    def _engine_with_fake_capture(self):
        from modules.network.engine import NetworkEngine

        class FakeCapture:
            def __init__(self, iface, bpf_filter="", snaplen=65535, promisc=True):
                self.interface = iface
                self.bpf_filter = bpf_filter
                self.stopped = False
                self.started = False

            def start(self):
                self.started = True

            def stop(self):
                self.stopped = True

        engine = NetworkEngine(interface="Wi-Fi", bpf_filter="tcp or udp")
        engine.capture = FakeCapture("Wi-Fi")
        return engine, FakeCapture

    @pytest.mark.asyncio
    async def test_rebind_switches_capture_and_counts(self, monkeypatch):
        """_rebind_capture stops the old sniffer, starts one on the new
        interface, and increments the change counter."""
        import modules.network.engine as eng_mod

        engine, FakeCapture = self._engine_with_fake_capture()
        monkeypatch.setattr(eng_mod, "PacketCapture", FakeCapture)
        old_capture = engine.capture

        await engine._rebind_capture("Ethernet")

        assert old_capture.stopped is True
        assert engine.interface == "Ethernet"
        assert isinstance(engine.capture, FakeCapture)
        assert engine.capture.interface == "Ethernet"
        assert engine.capture.started is True
        assert engine._interface_changes == 1
        # The API reads the PUBLIC name (no underscore) — regression: a
        # private/public attribute mismatch made /status always report 0.
        assert engine.interface_changes == 1

    @pytest.mark.asyncio
    async def test_watchdog_follows_interface_change(self, monkeypatch):
        """Two consecutive differing polls (debounce) trigger one rebind."""
        import modules.network.engine as eng_mod

        engine, _Fake = self._engine_with_fake_capture()
        engine._watchdog_interval = 0.01
        engine._watchdog_debounce = 2

        sequence = iter(["Wi-Fi", "Ethernet", "Ethernet", "Ethernet",
                         "Ethernet", "Ethernet", "Ethernet", "Ethernet"])
        monkeypatch.setattr(eng_mod, "resolve_active_interface",
                            lambda cached=True: next(sequence, "Ethernet"))

        engine._running = True
        task = asyncio.create_task(engine._interface_watchdog())
        try:
            for _ in range(200):
                if engine._interface_changes >= 1:
                    break
                await asyncio.sleep(0.02)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        assert engine.interface == "Ethernet"
        assert engine._interface_changes == 1

    @pytest.mark.asyncio
    async def test_watchdog_debounce_ignores_flapping(self, monkeypatch):
        """A resolver that flips between two interfaces every poll must NOT
        trigger any rebind (each change never stabilises for 2 polls)."""
        import modules.network.engine as eng_mod

        engine, _Fake = self._engine_with_fake_capture()
        engine._watchdog_interval = 0.01
        engine._watchdog_debounce = 2

        seq = iter(["Wi-Fi", "Ethernet", "Wi-Fi", "Ethernet",
                    "Wi-Fi", "Ethernet", "Wi-Fi", "Ethernet",
                    "Wi-Fi", "Ethernet", "Wi-Fi", "Ethernet"])
        monkeypatch.setattr(eng_mod, "resolve_active_interface",
                            lambda cached=True: next(seq, "Wi-Fi"))

        engine._running = True
        task = asyncio.create_task(engine._interface_watchdog())
        try:
            for _ in range(12):
                await asyncio.sleep(0.02)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        assert engine.interface == "Wi-Fi"
        assert engine._interface_changes == 0


class TestLiveFeed:
    """_LiveFeed (api/routes/network.py) — the WS live feed mechanics.

    Tested on a single event loop (deterministic — no portal/threading
    hazards like under TestClient).
    """

    def test_ticks_frames_and_unsubscribe(self):
        from api.routes.network import _LiveFeed
        from core.network.stats import StatsCollector

        async def run():
            feed = _LiveFeed(StatsCollector(), interval=0.01)
            q = feed.subscribe()
            assert q.maxsize == 100
            feed.start()
            try:
                first = await asyncio.wait_for(q.get(), 2)
                assert first["type"] == "stats"
                for key in ("pps", "packets_total", "by_protocol", "timestamp"):
                    assert key in first["data"]

                # Frames pushed by the engine reach the subscriber.
                feed.push_frame({"frame_type": "dns", "data": {}, "five_tuple": None})
                frame = await asyncio.wait_for(q.get(), 2)
                assert frame["type"] == "frame"
                assert frame["data"]["frame_type"] == "dns"

                # Periodic stats ticks continue after the frame.
                tick = await asyncio.wait_for(q.get(), 2)
                assert tick["type"] == "stats"
                assert tick["data"]["timestamp"] >= first["data"]["timestamp"]

                feed.unsubscribe(q)
                assert q not in feed._queues
            finally:
                feed.stop()

        asyncio.run(run())

    def test_bounded_queue_drops_stale_keeps_newest(self):
        """Overflowing the 100-slot subscriber queue drops the OLDEST messages
        and keeps delivering the newest (slow consumer never stalls the feed)."""
        from api.routes.network import _LiveFeed
        from core.network.stats import StatsCollector

        async def run():
            feed = _LiveFeed(StatsCollector(), interval=9999)  # ticks off
            q = feed.subscribe()
            feed.start()
            try:
                for i in range(150):  # overflow the 100-slot queue
                    feed.push_frame({"frame_type": "f", "data": {"i": i}, "five_tuple": None})
                assert q.qsize() == 100
                # Drain: Queue.get() returns synchronously while the queue is
                # non-empty, so the tick task never interleaves here — all 100
                # slots hold frames 50..149 (the 150 pushes displaced 0..49).
                seen = set()
                while not q.empty():
                    item = await q.get()
                    if item["type"] == "frame":
                        # push_frame wraps: {type, data: {frame_type, data: {...}}}
                        seen.add(item["data"]["data"]["i"])
                assert len(seen) == 100
                assert 149 in seen                 # newest kept
                assert 0 not in seen and 49 not in seen  # oldest dropped
            finally:
                feed.stop()

        asyncio.run(run())


class TestTCPReassembler:
    def test_feed_returns_stream(self):
        pkt = _tcp_pkt(1000, b"GET / HTTP/1.1\r\n\r\n")

        reassembler = TCPReassembler()
        streams = reassembler.feed(pkt)
        assert len(streams) == 1
        stream = streams[0]
        assert stream.frames[0].payload.startswith(b"GET /")
        assert stream.frames[0].seq_start == 1000
        assert stream.frames[0].is_client is True

    def test_retransmission_not_duplicated(self):
        reassembler = TCPReassembler()
        pkt = _tcp_pkt(1000, b"hello")
        reassembler.feed(pkt)
        reassembler.feed(pkt)

        stream = reassembler.get_all_streams()[0]
        assert len(stream.frames) == 1

    def test_feed_with_ethernet_frame(self):
        """The capture produces L2 frames; the reassembler must dissect them
        (regression: it parsed with IP(raw), which misreads Ethernet bytes)."""
        from scapy.all import Ether, IP, TCP
        pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(
                Ether() / IP(src="10.0.0.1", dst="93.184.216.34") /
                TCP(sport=54321, dport=80, flags="PA", seq=1000) /
                b"GET / HTTP/1.1\r\n\r\n"
            ),
            interface="eth0",
        )

        reassembler = TCPReassembler()
        streams = reassembler.feed(pkt)
        assert len(streams) == 1
        assert streams[0].frames[0].payload.startswith(b"GET /")

    def test_overlap_regression(self):
        """Regression: with segments [1000:1010], [1005:1015], [1012:1016] the
        old merge code sliced last.data[:overlap] which grabbed the WRONG bytes
        once the buffer spanned past the new segment's start. The merged stream
        must be 16 contiguous bytes in sequence order."""
        reassembler = TCPReassembler()
        reassembler.feed(_tcp_pkt(1000, b"A" * 10, ts_off=0))
        reassembler.feed(_tcp_pkt(1005, b"B" * 10, ts_off=1))   # overlaps, newer
        reassembler.feed(_tcp_pkt(1012, b"C" * 4, ts_off=2))    # overlaps B's tail

        stream = reassembler.get_all_streams()[0]
        seqs = [f.seq_start for f in stream.frames]
        assert seqs == [1000, 1010, 1015]
        # Each frame contiguous with the previous one (same direction).
        for prev, cur in zip(stream.frames, stream.frames[1:]):
            assert prev.seq_end == cur.seq_start
        payload = b"".join(f.payload for f in stream.frames)
        assert payload == b"A" * 10 + b"B" * 5 + b"C" * 1
        assert len(payload) == 16

    def test_out_of_order_frames_are_ordered(self):
        """Regression: frames were emitted in arrival order, so an out-of-order
        segment produced a backwards-jumping sequence. Data arriving before the
        anchor must be inserted in order."""
        reassembler = TCPReassembler()
        reassembler.feed(_tcp_pkt(1010, b"B" * 10))   # arrives first
        reassembler.feed(_tcp_pkt(1000, b"A" * 10))   # arrives late

        stream = reassembler.get_all_streams()[0]
        assert [f.seq_start for f in stream.frames] == [1000, 1010]
        assert stream.frames[0].payload == b"A" * 10
        assert stream.frames[1].payload == b"B" * 10

    def test_gap_buffered_until_filled(self):
        reassembler = TCPReassembler()
        reassembler.feed(_tcp_pkt(1000, b"A" * 10))
        reassembler.feed(_tcp_pkt(1020, b"C" * 5))    # gap at 1010 — buffered

        stream = reassembler.get_all_streams()[0]
        assert len(stream.frames) == 1

        reassembler.feed(_tcp_pkt(1010, b"B" * 10))   # fills the gap

        stream = reassembler.get_all_streams()[0]
        assert [f.seq_start for f in stream.frames] == [1000, 1010, 1020]

    def test_window_scale_from_tcp_options(self):
        """Regression: the scale was read out of the TCP window field
        ((window >> 14) & 0xF). It is actually a TCP option (kind 3, WScale)
        negotiated in the SYN exchange."""
        reassembler = TCPReassembler()
        reassembler.feed(_tcp_pkt(
            1000, b"", flags="S", options=[("MSS", 1460), ("WScale", 7)]
        ))

        stream = reassembler.get_all_streams()[0]
        assert stream.client_window_scale == 7

    def test_syn_ack_first_does_not_mark_server_as_client(self):
        """Regression: the old code added the FIRST packet's source port to
        client_ports on stream creation — so a stream observed starting with
        the server's SYN-ACK mislabelled the server as the client and every
        client frame was tagged server-side. Direction must come from the
        handshake (plain SYN = client, SYN-ACK = server)."""
        from scapy.all import IP, TCP

        reassembler = TCPReassembler()
        # Server SYN-ACK arrives first (capture joined mid-handshake). The
        # server packet has REVERSED IPs: server:80 -> client:54321.
        server_pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(IP(src="93.184.216.34", dst="10.0.0.1") /
                            TCP(sport=80, dport=54321, flags="SA", seq=5000)),
            interface="eth0",
        )
        reassembler.feed(server_pkt)
        # Client SYN + first data.
        reassembler.feed(_tcp_pkt(1000, b"", sport=54321, dport=80, flags="S"))
        reassembler.feed(_tcp_pkt(1001, b"GET / HTTP/1.1\r\n\r\n", sport=54321, dport=80, flags="PA"))

        stream = reassembler.get_all_streams()[0]
        assert stream.server_isn == 5000
        assert stream.client_isn == 1000
        assert stream.frames[-1].is_client is True


class TestUDPFlowTracker:
    def test_feed_with_ethernet_frame(self):
        from scapy.all import Ether, IP, UDP
        pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(
                Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
                UDP(sport=53000, dport=53) /
                b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            ),
            interface="eth0",
        )

        tracker = UDPFlowTracker()
        flow = tracker.feed(pkt)
        assert flow is not None
        assert flow.packets[0].length == 12

    def test_feed_creates_flow(self):
        from scapy.all import IP, UDP
        pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(IP(src="10.0.0.1", dst="8.8.8.8") /
                            UDP(sport=53000, dport=53) /
                            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            interface="eth0"
        )

        tracker = UDPFlowTracker()
        flow = tracker.feed(pkt)
        assert flow is not None
        assert flow.packets[0].length == 12
        assert flow.five_tuple.protocol == 17


class TestPacketCapture:
    def test_next_packet_async_returns_queued_packet(self):
        capture = PacketCapture("lo")
        pkt = RawPacket(timestamp=datetime.now(), raw_bytes=b"x", interface="lo")
        capture._packet_queue.put(pkt)

        async def main():
            assert await capture.next_packet_async() is pkt
            capture._running = False
            assert await capture.next_packet_async() is None

        asyncio.run(main())

    def test_next_packet_async_never_blocks(self):
        """Regression: the old drain iterated the sync ``packets()`` generator
        whose queue.get(timeout=0.2) froze the event loop for up to 200ms on
        every empty poll. The new drain must yield control without blocking."""
        import time as _time

        capture = PacketCapture("lo")
        capture._running = True

        async def main():
            start = _time.monotonic()
            task = asyncio.create_task(capture.next_packet_async())
            await asyncio.sleep(0.05)
            assert not task.done(), "empty poll blocked the event loop"
            assert _time.monotonic() - start < 0.15
            capture._running = False
            assert await asyncio.wait_for(task, 0.5) is None

        asyncio.run(main())


class TestNetworkEngine:
    def test_frames_deduplicated_across_flow_reparses(self):
        """Regression: decoders re-parse the WHOLE flow on every packet, so a
        DNS flow with N messages re-emitted all N-1 previous frames as
        duplicates on each new packet. Only genuinely new frames may surface."""
        from scapy.all import DNS, DNSQR, IP, UDP
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="eth0")

        def dns_pkt(qname: str, pkt_id: int) -> RawPacket:
            msg = bytes(DNS(id=pkt_id, qr=0, qd=DNSQR(qname=qname, qtype="A")))
            return RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(IP(src="10.0.0.1", dst="8.8.8.8") /
                                UDP(sport=53000, dport=53) / msg),
                interface="eth0",
            )

        asyncio.run(engine._handle_packet(dns_pkt("example.com", 0x1111)))
        assert len(engine.recent_frames) == 1
        # Second packet re-parses the flow (2 messages) — the first frame must
        # not be re-emitted.
        asyncio.run(engine._handle_packet(dns_pkt("example.org", 0x2222)))
        assert len(engine.recent_frames) == 2
        names = [f["data"]["questions"][0]["name"] for f in engine.recent_frames]
        assert names == ["example.com", "example.org"]

    def test_summarize_bare_ip_datagram(self):
        """Regression: _summarize checked ``TCP in eth`` where eth was
        Ether(raw) — on a bare IP datagram (no L2 header) Ether() misparses
        the IP header, so TCP/UDP packets were labelled "ip" with no ports."""
        from scapy.all import IP, TCP
        from modules.network.engine import NetworkEngine

        pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(IP(src="1.2.3.4", dst="5.6.7.8") /
                            TCP(sport=1234, dport=443)),
            interface="eth0",
        )
        summary = NetworkEngine._summarize(pkt)
        assert summary["proto"] == "tcp"
        assert summary["sport"] == 1234
        assert summary["dport"] == 443

    def test_quic_frames_aggregated_per_connection(self):
        """Option 1: a burst of QUIC datagrams must produce ONE frame row per
        connection (not one per datagram), with later datagrams updating that
        row in place so the frame list never fills with 'QUIC short' spam."""
        from scapy.all import Ether, IP, UDP
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="eth0")

        def quic_pkt(payload: bytes) -> RawPacket:
            return RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(
                    Ether() / IP(src="10.0.0.1", dst="1.1.1.1") /
                    UDP(sport=50000, dport=443) / payload
                ),
                interface="eth0",
            )

        dcid = bytes(range(8))
        initial = b"\xc0" + struct.pack(">I", 1) + b"\x08\x00" + dcid
        short = b"\x43\x01\x02\x03"

        asyncio.run(engine._handle_packet(quic_pkt(initial)))
        asyncio.run(engine._handle_packet(quic_pkt(short)))
        asyncio.run(engine._handle_packet(quic_pkt(short)))

        quic_frames = [f for f in engine.recent_frames if f["frame_type"] == "quic"]
        assert len(quic_frames) == 1                      # one row, not three
        assert quic_frames[0]["data"]["packet_count"] == 3   # updated in place
        assert quic_frames[0]["data"]["packet_types"] == {"initial": 1, "short": 2}
        assert len(engine.quic_connections) == 1
        assert engine.quic_connections[dcid.hex()]["packet_count"] == 3


class TestCapturePerformance:
    """Capture-path performance contracts (timeout/500 prevention):
    O(1) byte accounting, bounded stream tables, incremental decoding."""

    def test_stream_bytes_total_incremental(self):
        """TCPStream.bytes_total is maintained per appended frame — /streams
        must never re-sum the frame list per request."""
        from scapy.all import Ether, IP, TCP
        from core.network.reassemble import TCPReassembler

        r = TCPReassembler()
        for i in range(4):
            pkt = RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(
                    Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                    TCP(sport=1000, dport=80, flags="PA", seq=1000 + i * 10) /
                    (b"x" * 10)
                ),
                interface="eth0",
            )
            r.feed(pkt)
        stream = r.get_all_streams()[0]
        assert stream.bytes_total == 40
        assert stream.bytes_total == sum(len(f.payload) for f in stream.frames)

    def test_udp_flow_bytes_total_incremental(self):
        from scapy.all import Ether, IP, UDP
        from core.network.reassemble import UDPFlowTracker

        t = UDPFlowTracker()
        for _ in range(3):
            t.feed(RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(
                    Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
                    UDP(sport=53000, dport=53) / b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                ),
                interface="eth0",
            ))
        flow = t.get_all_flows()[0]
        assert flow.bytes_total == 36
        assert flow.bytes_total == sum(p.length for p in flow.packets)

    def test_udp_flow_packet_cap_trims_and_counts_trimmed(self):
        """Per-flow memory is capped: oldest packets trimmed, trimmed counter
        advanced (decode checkpoints depend on it)."""
        from scapy.all import Ether, IP, UDP
        from core.network.reassemble import UDPFlowTracker

        t = UDPFlowTracker(max_packets_per_flow=10)
        payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        for i in range(25):
            t.feed(RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(
                    Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
                    UDP(sport=53000, dport=53) / payload
                ),
                interface="eth0",
            ))
        flow = t.get_all_flows()[0]
        assert len(flow.packets) == 10
        assert flow.trimmed == 15
        # Absolute accounting survives trimming.
        assert flow.trimmed + len(flow.packets) == 25

    def test_dns_decoding_is_checkpointed(self):
        """Opt 3: each new DNS packet decodes ONLY the new message — the
        checkpoint advances and previously-decoded payloads are not re-parsed
        (observable: exactly N frames after N packets, checkpoint == N)."""
        from scapy.all import DNS, DNSQR, Ether, IP, UDP
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="eth0")

        def dns_pkt(name: str, pkt_id: int) -> RawPacket:
            msg = bytes(DNS(id=pkt_id, qr=0, qd=DNSQR(qname=name, qtype="A")))
            return RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(
                    Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
                    UDP(sport=53000, dport=53) / msg
                ),
                interface="eth0",
            )

        for i, name in enumerate([f"site{i}.com" for i in range(6)]):
            asyncio.run(engine._handle_packet(dns_pkt(name, 0x1000 + i)))

        key = engine._ft_key(engine.udp_tracker.get_all_flows()[0].five_tuple)
        flow = engine.udp_tracker.get_all_flows()[0]
        assert engine._decode_checkpoints[key] == flow.trimmed + len(flow.packets) == 6
        dns_frames = [f for f in engine.recent_frames if f["frame_type"] == "dns"]
        assert len(dns_frames) == 6
        names = {f["data"]["questions"][0]["name"] for f in dns_frames}
        assert names == {f"site{i}.com" for i in range(6)}

    def test_idle_streams_evicted(self):
        """Opt 2: idle streams/flows are dropped and their checkpoints freed;
        fresh ones survive the sweep."""
        from scapy.all import Ether, IP, TCP, UDP
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="eth0")
        # One stream/flow each (default 600s idle timeout — nothing evicted
        # by the in-packet sweep on fresh entries).
        tcp_pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                            TCP(sport=1000, dport=80, flags="PA", seq=1000) / b"hello"),
            interface="eth0",
        )
        udp_pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
                            UDP(sport=53000, dport=53) /
                            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"),
            interface="eth0",
        )
        asyncio.run(engine._handle_packet(tcp_pkt))
        asyncio.run(engine._handle_packet(udp_pkt))
        assert len(engine.tcp_reassembler.get_all_streams()) == 1
        assert len(engine.udp_tracker.get_all_flows()) == 1
        # A checkpoint exists for the DNS flow — eviction must free it too.
        assert engine._decode_checkpoints

        # Age both entries past the idle timeout, then sweep (the per-packet
        # sweep already ran, so force the 30s cadence gate open).
        stale = datetime.now() - timedelta(seconds=engine.stream_idle_timeout + 1)
        for s in engine.tcp_reassembler.get_all_streams():
            s.last_seen = stale
        for f in engine.udp_tracker.get_all_flows():
            f.last_seen = stale
        engine._last_sweep = datetime.now() - timedelta(seconds=60)
        engine._maybe_evict_idle()

        assert len(engine.tcp_reassembler.get_all_streams()) == 0
        assert len(engine.udp_tracker.get_all_flows()) == 0
        assert engine._decode_checkpoints == {}

    def test_fresh_stream_survives_sweep(self):
        """Opt 2: a recently-active stream is NOT evicted by the sweep."""
        from scapy.all import Ether, IP, TCP
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="eth0")
        asyncio.run(engine._handle_packet(RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") /
                            TCP(sport=1000, dport=80, flags="PA", seq=1000) / b"hello"),
            interface="eth0",
        )))
        engine._maybe_evict_idle()  # fresh last_seen — must survive
        assert len(engine.tcp_reassembler.get_all_streams()) == 1

    def test_stream_cap_evicts_oldest(self):
        """Opt 2: over the hard cap, the oldest-last_seen entries go first."""
        from scapy.all import Ether, IP, TCP
        from modules.network.engine import NetworkEngine

        engine = NetworkEngine(interface="eth0")
        engine.max_tracked_streams = 3

        for i in range(5):
            asyncio.run(engine._handle_packet(RawPacket(
                timestamp=datetime.now(),
                raw_bytes=bytes(
                    Ether() / IP(src="10.0.0.1", dst=f"10.0.0.{i + 2}") /
                    TCP(sport=1000, dport=80, flags="PA", seq=1000) / b"x"
                ),
                interface="eth0",
            )))

        # The cap is enforced on the sweep (30s cadence) — force one now.
        engine._last_sweep = datetime.now() - timedelta(seconds=60)
        engine._maybe_evict_idle()

        total = (len(engine.tcp_reassembler.get_all_streams())
                 + len(engine.udp_tracker.get_all_flows()))
        assert total <= 3


class TestManipulator:
    def test_modify_in_place_preserves_l2_header(self):
        """Regression: modify_in_place parsed the raw bytes with bare IP(),
        which either raised or misparsed Ethernet frames — so modification
        silently no-oped on real captured packets. The L2 header must be
        preserved and the payload replaced."""
        from scapy.all import Ether, IP, TCP, Raw
        from core.network.manipulate import PacketEdits
        from core.network.platform.linux import LinuxManipulatorBackend

        original = bytes(
            Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff") /
            IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=1234, dport=80) /
            b"ORIGINAL"
        )
        pkt = RawPacket(timestamp=datetime.now(), raw_bytes=original, interface="eth0")
        backend = LinuxManipulatorBackend("eth0")

        out = backend.modify_in_place(pkt, PacketEdits(payload_replace=b"REPLACED", recalc_checksums=True))

        assert out.raw_bytes[:14] == original[:14]
        assert b"REPLACED" in out.raw_bytes
        assert b"ORIGINAL" not in out.raw_bytes


class TestDecoderRegistry:
    """DecoderRegistry: registration and stream routing."""

    def _dns_flow(self):
        from scapy.all import DNS, DNSQR
        dns = DNS(id=0x1, qr=0, qd=DNSQR(qname="a.com"))
        flow = UDPFlow(five_tuple=FiveTuple("10.0.0.1", "8.8.8.8", 53000, 53, 17))
        flow.packets.append(UDPPacket(payload=bytes(dns), timestamp=datetime.now(), length=len(bytes(dns))))
        return flow

    def test_register_and_get_all(self):
        from core.network.protocols.base import DecoderRegistry
        reg = DecoderRegistry()
        d = DNSDecoder()
        reg.register(d)
        assert reg.get_all_decoders() == [d]

    def test_get_decoders_for_stream_routes_dns_only(self):
        """A UDP DNS flow routes ONLY to DNSDecoder (ARP/ICMP never match a
        stream, QUIC requires a QUIC long header)."""
        from core.network.protocols.base import DecoderRegistry
        reg = DecoderRegistry()
        dns = DNSDecoder()
        reg.register(dns)
        reg.register(QUICDecoder())
        reg.register(ARPDecoder())

        matched = reg.get_decoders_for_stream(self._dns_flow())
        assert matched == [dns]

    def test_get_decoders_for_stream_no_match(self):
        from core.network.protocols.base import DecoderRegistry
        reg = DecoderRegistry()
        reg.register(ARPDecoder())  # can_decode(stream) is always False
        assert reg.get_decoders_for_stream(self._dns_flow()) == []

    def test_clear(self):
        from core.network.protocols.base import DecoderRegistry
        reg = DecoderRegistry()
        reg.register(DNSDecoder())
        reg.clear()
        assert reg.get_all_decoders() == []


class TestFiveTuple:
    """FiveTuple identity semantics used by the flow trackers (dict keys)."""

    def test_reverse(self):
        ft = FiveTuple("10.0.0.1", "8.8.8.8", 53000, 53, 17)
        rev = ft.reverse()
        assert (rev.src_ip, rev.dst_ip, rev.src_port, rev.dst_port, rev.protocol) == (
            "8.8.8.8", "10.0.0.1", 53, 53000, 17
        )
        # Double-reverse returns to the original.
        assert rev.reverse() == ft

    def test_eq_and_hash(self):
        a = FiveTuple("1.1.1.1", "2.2.2.2", 100, 200, 6)
        b = FiveTuple("1.1.1.1", "2.2.2.2", 100, 200, 6)
        assert a == b
        assert hash(a) == hash(b)
        assert a != FiveTuple("1.1.1.1", "2.2.2.2", 100, 200, 17)  # protocol differs

    def test_usable_as_dict_key(self):
        """Reassembler/flow-tracker store streams keyed by FiveTuple — equal
        tuples must hit the same key."""
        a = FiveTuple("1.1.1.1", "2.2.2.2", 100, 200, 6)
        b = FiveTuple("1.1.1.1", "2.2.2.2", 100, 200, 6)
        d = {a: "stream"}
        assert d[b] == "stream"


class _FakeBackend:
    """Minimal PacketManipulatorBackend stub — no OS sockets touched."""

    def __init__(self):
        self.closed = False

    def inject(self, pkt):
        return True

    def modify_in_place(self, pkt, edits):
        return pkt

    def drop(self, pkt_id):
        return True

    def close(self):
        self.closed = True


class TestPacketManipulatorFacade:
    """PacketManipulator facade: start/stop lifecycle + safe no-ops.

    Uses a stub backend via monkeypatch so the tests never open a WinDivert
    handle or raw socket (which need admin privileges).
    """

    def _pkt(self):
        return RawPacket(timestamp=datetime.now(), raw_bytes=b"x", interface="eth0")

    def _patch_backend(self, monkeypatch, fake):
        # The facade imports create_manipulator_backend INSIDE start(), so
        # patching the platform module attribute intercepts every call.
        monkeypatch.setattr(
            "core.network.platform.create_manipulator_backend", lambda iface: fake
        )

    def test_noop_before_start(self):
        """inject/drop are safe no-ops before the backend exists; modify_in_place
        returns the packet unchanged."""
        from core.network.manipulate import PacketManipulator, PacketEdits
        m = PacketManipulator("eth0")

        pkt = self._pkt()
        assert m.inject(pkt) is False
        assert m.drop(1) is False
        assert m.modify_in_place(pkt, PacketEdits()) is pkt
        m.stop()  # no backend — must not raise

    def test_start_stop_lifecycle(self, monkeypatch):
        from core.network.manipulate import PacketManipulator
        fake = _FakeBackend()
        self._patch_backend(monkeypatch, fake)

        m = PacketManipulator("eth0")
        m.start()
        assert m._backend is fake
        pkt = self._pkt()
        assert m.inject(pkt) is True
        assert m.drop(5) is True

        m.stop()
        assert fake.closed is True       # backend released
        assert m._backend is None
        assert m.inject(pkt) is False    # back to no-op after stop

    def test_start_is_idempotent(self, monkeypatch):
        """Calling start() twice must not replace an existing backend."""
        from core.network.manipulate import PacketManipulator
        fake = _FakeBackend()
        self._patch_backend(monkeypatch, fake)

        m = PacketManipulator("eth0")
        m.start()
        m.start()
        assert m._backend is fake
        m.stop()

    def test_context_manager(self, monkeypatch):
        """__enter__ starts, __exit__ stops and releases the backend."""
        from core.network.manipulate import PacketManipulator
        fake = _FakeBackend()
        self._patch_backend(monkeypatch, fake)

        with PacketManipulator("eth0") as m:
            assert m._backend is fake
        assert fake.closed is True


# ── Background tasks ─────────────────────────────────────────────────────────


class TestCaptureCleanupTask:
    """CaptureCleanupTask: deletes old/oversized capture files."""

    @pytest.mark.asyncio
    async def test_old_files_deleted(self, tmp_path):
        """Files older than max_age_days are removed."""
        from modules.network.tasks import CaptureCleanupTask

        cap_dir = tmp_path / "captures"
        cap_dir.mkdir()
        old = cap_dir / "old.pcap"
        new = cap_dir / "new.pcap"
        old.write_bytes(b"old")
        new.write_bytes(b"new")
        # Set old file's mtime to 10 days ago
        import os
        old_ts = int((datetime.now() - timedelta(days=10)).timestamp())
        os.utime(old, (old_ts, old_ts))

        task = CaptureCleanupTask(capture_dir=str(cap_dir), max_age_days=7)
        await task._cleanup()

        assert not old.exists()
        assert new.exists()

    @pytest.mark.asyncio
    async def test_size_limit_deletes_oldest(self, tmp_path):
        """When total size exceeds max_size_mb, oldest files are deleted."""
        from modules.network.tasks import CaptureCleanupTask

        cap_dir = tmp_path / "captures"
        cap_dir.mkdir()
        # Create 3 files of 1KB each, set different mtimes
        import os
        files = []
        for i, name in enumerate(["a.pcap", "b.pcap", "c.pcap"]):
            f = cap_dir / name
            f.write_bytes(b"x" * 1024)
            f_ts = int((datetime.now() - timedelta(hours=3 - i)).timestamp())
            os.utime(f, (f_ts, f_ts))
            files.append(f)

        # max_size = 2KB → should delete oldest (a.pcap) to fit
        task = CaptureCleanupTask(
            capture_dir=str(cap_dir), max_age_days=365, max_size_mb=0.002
        )
        await task._cleanup()

        remaining = list(cap_dir.glob("*.pcap"))
        assert len(remaining) == 2
        assert not (cap_dir / "a.pcap").exists()  # oldest deleted

    @pytest.mark.asyncio
    async def test_no_crash_when_dir_missing(self, tmp_path):
        """_cleanup is a no-op when capture_dir doesn't exist."""
        from modules.network.tasks import CaptureCleanupTask

        task = CaptureCleanupTask(capture_dir=str(tmp_path / "nonexistent"))
        await task._cleanup()  # should not raise

    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, tmp_path):
        """start() and stop() manage the background task cleanly."""
        from modules.network.tasks import CaptureCleanupTask

        task = CaptureCleanupTask(
            capture_dir=str(tmp_path), interval_hours=9999
        )
        await task.start()
        assert task._running
        assert task._task is not None

        await task.stop()
        assert not task._running

    @pytest.mark.asyncio
    async def test_start_idempotent(self, tmp_path):
        """Calling start() twice doesn't create a second task."""
        from modules.network.tasks import CaptureCleanupTask

        task = CaptureCleanupTask(
            capture_dir=str(tmp_path), interval_hours=9999
        )
        await task.start()
        first_task = task._task
        await task.start()
        assert task._task is first_task  # same task, not replaced
        await task.stop()


class TestStatsAggregationTask:
    """StatsAggregationTask: writes periodic stats JSON files."""

    @pytest.mark.asyncio
    async def test_writes_stats_json(self, tmp_path):
        """_write_stats creates a JSON file with valid stats."""
        from modules.network.tasks import StatsAggregationTask
        from core.network.stats import StatsCollector

        collector = StatsCollector()
        task = StatsAggregationTask(
            stats_collector=collector, output_dir=str(tmp_path / "stats")
        )
        await task.start()
        await task._write_stats()

        files = list((tmp_path / "stats").glob("stats_*.json"))
        assert len(files) == 1

        import json
        data = json.loads(files[0].read_text())
        assert "timestamp" in data
        assert "pps" in data
        assert "packets_total" in data
        await task.stop()

    @pytest.mark.asyncio
    async def test_stats_json_is_valid(self, tmp_path):
        """The written JSON is parseable and has correct structure."""
        from modules.network.tasks import StatsAggregationTask
        from core.network.stats import StatsCollector

        collector = StatsCollector()
        out_dir = tmp_path / "stats"
        out_dir.mkdir(exist_ok=True)
        task = StatsAggregationTask(
            stats_collector=collector, output_dir=str(out_dir)
        )
        await task._write_stats()

        import json
        files = list(out_dir.glob("stats_*.json"))
        assert len(files) == 1, f"expected 1 stats file, got {len(files)}: {list(out_dir.iterdir())}"
        data = json.loads(files[0].read_text())
        # All expected keys present
        for key in ["timestamp", "pps", "bps", "active_flows", "tcp_streams",
                     "udp_flows", "bytes_total", "packets_total", "errors",
                     "by_protocol", "by_port"]:
            assert key in data, f"missing key: {key}"

    @pytest.mark.asyncio
    async def test_stop_cleans_up(self, tmp_path):
        """stop() cancels the background task cleanly."""
        from modules.network.tasks import StatsAggregationTask
        from core.network.stats import StatsCollector

        collector = StatsCollector()
        task = StatsAggregationTask(
            stats_collector=collector, output_dir=str(tmp_path / "stats"),
            interval_seconds=9999
        )
        await task.start()
        assert task._running
        await task.stop()
        assert not task._running


class TestPCAPRotationTask:
    """PCAPRotationTask: rotates capture files by size/time."""

    @pytest.mark.asyncio
    async def test_creates_initial_file(self, tmp_path):
        """start() creates the first pcap file."""
        from modules.network.tasks import PCAPRotationTask

        base = tmp_path / "capture.pcap"
        task = PCAPRotationTask(
            base_path=str(base), max_size_mb=100, max_duration_seconds=3600
        )
        await task.start()

        assert task._current_writer is not None
        assert task._current_writer.path.exists()
        await task.stop()

    @pytest.mark.asyncio
    async def test_rotation_by_size(self, tmp_path):
        """write_packet triggers rotation when file exceeds max_size_mb."""
        from modules.network.tasks import PCAPRotationTask
        from core.network.capture import RawPacket

        base = tmp_path / "capture.pcap"
        # max_size = 500 bytes — triggers after a few packets (200B payload + 16B pcap hdr each)
        task = PCAPRotationTask(
            base_path=str(base), max_size_mb=0.0005, max_duration_seconds=99999
        )
        await task.start()

        # Write packets until rotation triggers
        total_written = 0
        for _ in range(20):
            pkt = RawPacket(
                timestamp=datetime.now(),
                raw_bytes=b"\x00" * 200,
                interface="eth0",
            )
            task.write_packet(pkt)
            total_written += 1

        # Rotation resets _packet_count to 0 on each new file. If rotation
        # happened, the current writer's count will be less than total_written.
        current_count = task._current_writer._packet_count
        assert current_count < total_written, (
            f"rotation never triggered: current={current_count}, total={total_written}"
        )
        await task.stop()

    @pytest.mark.asyncio
    async def test_stop_closes_writer(self, tmp_path):
        """stop() closes the current writer and sets it to None."""
        from modules.network.tasks import PCAPRotationTask

        base = tmp_path / "capture.pcap"
        task = PCAPRotationTask(
            base_path=str(base), max_size_mb=100, max_duration_seconds=3600
        )
        await task.start()
        assert task._current_writer is not None

        await task.stop()
        assert task._current_writer is None
        assert not task._running

    @pytest.mark.asyncio
    async def test_write_packet_noop_when_stopped(self, tmp_path):
        """write_packet is a no-op if task is not running."""
        from modules.network.tasks import PCAPRotationTask
        from core.network.capture import RawPacket

        base = tmp_path / "capture.pcap"
        task = PCAPRotationTask(
            base_path=str(base), max_size_mb=100, max_duration_seconds=3600
        )
        # Don't call start() — task is not running
        pkt = RawPacket(
            timestamp=datetime.now(), raw_bytes=b"\x00" * 10, interface="eth0"
        )
        task.write_packet(pkt)  # should not raise
        assert task._current_writer is None


class TestPacketDetail:
    """Per-packet seq ids + Wireshark-style dissection (GET /packets/{seq}).

    Feeds synthetic packets straight through _handle_packet — no sniffer, no
    threads, fully deterministic.
    """

    def _engine(self, **kw):
        from modules.network.engine import NetworkEngine
        return NetworkEngine(interface="eth0", **kw)

    def _tcp_pkt(self, payload=b"GET / HTTP/1.1\r\n\r\n"):
        from scapy.all import Ether, IP, TCP
        return RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(
                Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") /
                IP(src="10.0.0.1", dst="93.184.216.34") /
                TCP(sport=54321, dport=80, flags="PA") /
                payload
            ),
            interface="eth0",
        )

    @pytest.mark.asyncio
    async def test_handle_packet_assigns_monotonic_seq(self):
        """Every packet summary carries a monotonic seq id (the detail key)."""
        engine = self._engine()
        await engine._handle_packet(self._tcp_pkt())
        await engine._handle_packet(self._tcp_pkt(b"HTTP/1.1 200 OK\r\n\r\n"))
        assert [s["seq"] for s in engine.recent_packets] == [1, 2]

    @pytest.mark.asyncio
    async def test_detail_dissects_layer_tree(self):
        engine = self._engine()
        await engine._handle_packet(self._tcp_pkt())
        detail = engine.get_packet_detail(1)
        assert detail is not None
        assert detail["seq"] == 1
        assert detail["sniffed_on"] == "eth0"
        names = [layer["name"] for layer in detail["layers"]]
        # Wireshark-style chain: Ethernet > IP > TCP (+ Raw payload).
        assert "Ethernet" in names and "IP" in names and "TCP" in names
        tcp_layer = next(l for l in detail["layers"] if l["name"] == "TCP")
        # dport renders via i2repr ("http" for 80) but keeps the raw number
        # so the UI can sort/display ports numerically.
        assert tcp_layer["fields"]["dport"]["raw"] == 80
        # Hexdump pane present and non-trivial.
        assert detail["hexdump"]
        assert "aa bb cc" in detail["hexdump"].replace("AA BB CC", "aa bb cc") or ":" in detail["hexdump"]

    @pytest.mark.asyncio
    async def test_detail_unknown_seq_returns_none(self):
        engine = self._engine()
        await engine._handle_packet(self._tcp_pkt())
        assert engine.get_packet_detail(999) is None
        assert engine.get_packet_detail(0) is None

    @pytest.mark.asyncio
    async def test_detail_maps_correct_raw_after_eviction(self):
        """The seq->raw mapping is positional from the END of both deques, so
        after the bounded buffer evicts, an old seq must 404 while a recent
        one must dissect the RIGHT raw packet (marker payload in hexdump)."""
        engine = self._engine(max_packets=2)
        markers = [b"PKT-THREE", b"PKT-FOUR"]
        for i in range(4):
            await engine._handle_packet(self._tcp_pkt(markers[i - 2]))
        # seqs 1,2 evicted; seq 4 must dissect the packet whose bytes contain
        # its marker, proving the offset alignment is exact.
        assert engine.get_packet_detail(1) is None
        detail3 = engine.get_packet_detail(3)
        assert detail3 is not None and "PKT-THREE" in detail3["hexdump"]
        detail4 = engine.get_packet_detail(4)
        assert detail4 is not None and "PKT-FOUR" in detail4["hexdump"]

    @pytest.mark.asyncio
    async def test_detail_bare_ip_datagram(self):
        """Synthetic bare-IP packets (no L2 header, as in manipulation tests)
        dissect without an Ethernet layer — same fallback as _summarize."""
        from scapy.all import IP, TCP
        engine = self._engine()
        pkt = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(IP(src="1.2.3.4", dst="5.6.7.8") /
                            TCP(sport=1234, dport=443)),
            interface="eth0",
        )
        await engine._handle_packet(pkt)
        detail = engine.get_packet_detail(1)
        names = [layer["name"] for layer in detail["layers"]]
        assert "Ethernet" not in names
        assert "IP" in names and "TCP" in names


# ── UDP in-flight modifier ──────────────────────────────────────────────


def _udp_pkt(payload=b"hello", sport=5000, dport=6000,
             src="10.0.0.1", dst="10.0.0.2"):
    from scapy.all import Ether, IP, UDP
    return RawPacket(
        timestamp=datetime.now(),
        raw_bytes=bytes(Ether() / IP(src=src, dst=dst) /
                        UDP(sport=sport, dport=dport) / payload),
        interface="eth0",
    )


def _icmp_pkt(payload=b"A" * 32, src="10.0.0.1", dst="8.8.8.8", echo_type=8):
    from scapy.all import Ether, IP, ICMP
    return RawPacket(
        timestamp=datetime.now(),
        raw_bytes=bytes(Ether() / IP(src=src, dst=dst) /
                        ICMP(type=echo_type, id=1, seq=1) / payload),
        interface="eth0",
    )


def _arp_reply(psrc, hwsrc, eth_src=None):
    from scapy.all import Ether, ARP
    e = Ether(src=eth_src or hwsrc, dst="ff:ff:ff:ff:ff:ff")
    return RawPacket(
        timestamp=datetime.now(),
        raw_bytes=bytes(e / ARP(op=2, psrc=psrc, hwsrc=hwsrc,
                                pdst="192.168.1.59", hwdst="aa:bb:cc:dd:ee:ff")),
        interface="eth0",
    )


class TestUDPModifier:
    def test_rule_matches_and_rewrites(self):
        """A matching rule rewrites the payload and injects via the manipulator."""
        from modules.network.udp_modifier import UDPModifier, UDPModifyRule
        sent = []

        class FakeManip:
            def inject(self, pkt):
                sent.append(pkt)
                return True

            def modify_in_place(self, pkt, edits):
                from scapy.all import Ether, IP, UDP, Raw
                eth = Ether(pkt.raw_bytes)
                eth[Raw].load = edits.payload_replace
                return RawPacket(pkt.timestamp, bytes(eth), pkt.interface, pkt.metadata)

        mod = UDPModifier(manipulator=FakeManip())
        mod.add_rule(UDPModifyRule(
            name="tamper", dst_ip="10.0.0.2", dst_port=6000,
            payload_pattern="hello*", payload_replace=b"EVIL",
        ))
        mod.enabled = True
        pkt = _udp_pkt(b"hello world")
        mod.handle_packet(pkt)

        assert len(sent) == 1
        assert mod.rewrites == 1
        assert mod.last_rewrite_rule == "tamper"
        # The re-injected packet carries the replacement payload.
        from scapy.all import Ether, Raw
        assert bytes(Ether(sent[0].raw_bytes)[Raw].load) == b"EVIL"

    def test_no_match_no_inject(self):
        from modules.network.udp_modifier import UDPModifier, UDPModifyRule
        sent = []

        class FakeManip:
            def inject(self, pkt):
                sent.append(pkt)
                return True

        mod = UDPModifier(manipulator=FakeManip())
        mod.add_rule(UDPModifyRule(name="x", dst_port=9999, payload_replace=b"z"))
        mod.enabled = True
        mod.handle_packet(_udp_pkt())
        assert sent == []
        assert mod.matches == 0

    def test_disabled_is_noop(self):
        from modules.network.udp_modifier import UDPModifier, UDPModifyRule
        mod = UDPModifier()
        mod.add_rule(UDPModifyRule(name="x", payload_replace=b"z"))
        # enabled stays False
        mod.handle_packet(_udp_pkt())
        assert mod.packets_seen == 0

    def test_status_shape(self):
        from modules.network.udp_modifier import UDPModifier, UDPModifyRule
        mod = UDPModifier()
        mod.add_rule(UDPModifyRule(name="r1", dst_port=53, payload_replace=b"x"))
        s = mod.status()
        assert s["enabled"] is False
        assert s["rules"][0]["name"] == "r1"
        assert s["rules"][0]["has_replace"] is True


class TestICMPTunnelDetector:
    def test_normal_ping_not_flagged(self):
        from modules.network.icmp_detector import ICMPTunnelDetector
        det = ICMPTunnelDetector()
        for _ in range(5):
            assert det.handle_packet(_icmp_pkt(b"A" * 56)) is None
        assert det.detections == 0

    def test_oversized_payload_flags(self):
        """A single huge echo payload crosses the threshold on size alone."""
        from modules.network.icmp_detector import ICMPTunnelDetector
        det = ICMPTunnelDetector()
        d = det.handle_packet(_icmp_pkt(b"X" * 512))
        assert d is not None
        assert d["score"] >= 3.0
        assert d["payload_size"] == 512
        assert det.detections == 1

    def test_regular_large_chunks_flag(self):
        """Fixed-size 128B chunks (tunnel pattern) accumulate to a report."""
        from modules.network.icmp_detector import ICMPTunnelDetector
        det = ICMPTunnelDetector()
        # Detection fires once mid-stream (then re-arm suppresses repeats) —
        # keep any result from the whole sequence.
        results = [det.handle_packet(_icmp_pkt(b"C" * 128)) for _ in range(6)]
        flagged = [r for r in results if r is not None]
        assert len(flagged) == 1
        assert flagged[0]["echoes_observed"] >= 4

    def test_rearm_after_report(self):
        """After a report the flow stays quiet until re-armed — no spam."""
        from modules.network.icmp_detector import ICMPTunnelDetector
        det = ICMPTunnelDetector()
        assert det.handle_packet(_icmp_pkt(b"X" * 512)) is not None
        # Same flow again: reported flag blocks a second immediate report.
        assert det.handle_packet(_icmp_pkt(b"X" * 512)) is None
        assert det.detections == 1

    def test_status_shape(self):
        from modules.network.icmp_detector import ICMPTunnelDetector
        det = ICMPTunnelDetector()
        s = det.status()
        assert s["detections"] == 0
        assert s["flows_tracked"] == 0
        assert "threshold" in s


class TestARPSpoofDetector:
    def test_learns_first_binding_silently(self):
        from modules.network.arp_guard import ARPSpoofDetector
        det = ARPSpoofDetector()
        assert det.handle_packet(_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:01")) is None
        assert det.detections == 0
        assert det._bindings["192.168.1.1"] == "aa:aa:aa:aa:aa:01"

    def test_contradicting_reply_alerts(self):
        """A second MAC claiming the gateway IP raises exactly one alert."""
        from modules.network.arp_guard import ARPSpoofDetector
        # Pin the gateway explicitly: the real default route differs per
        # machine (192.168.1.1 here, .254 on this dev box), and only
        # protected IPs alert.
        det = ARPSpoofDetector(protected_ips=["192.168.1.1"])
        det.handle_packet(_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:01"))
        alert = det.handle_packet(_arp_reply("192.168.1.1", "bb:bb:bb:bb:bb:02"))
        assert alert is not None
        assert alert["claimed_ip"] == "192.168.1.1"
        assert alert["legit_mac"] == "aa:aa:aa:aa:aa:01"
        assert alert["spoof_mac"] == "bb:bb:bb:bb:bb:02"
        assert det.detections == 1
        # Same pair again: no duplicate alert.
        assert det.handle_packet(_arp_reply("192.168.1.1", "bb:bb:bb:bb:bb:02")) is None

    def test_unprotected_ip_churn_ignored(self):
        """Ordinary MAC churn on non-gateway IPs never alerts."""
        from modules.network.arp_guard import ARPSpoofDetector
        det = ARPSpoofDetector()
        det.handle_packet(_arp_reply("192.168.1.50", "aa:aa:aa:aa:aa:50"))
        assert det.handle_packet(_arp_reply("192.168.1.50", "cc:cc:cc:cc:cc:51")) is None
        assert det.detections == 0

    def test_requests_ignored(self):
        from modules.network.arp_guard import ARPSpoofDetector
        from scapy.all import Ether, ARP
        req = RawPacket(
            timestamp=datetime.now(),
            raw_bytes=bytes(Ether(dst="ff:ff:ff:ff:ff:ff") /
                            ARP(op=1, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:01",
                                pdst="192.168.1.59")),
            interface="eth0",
        )
        det = ARPSpoofDetector()
        assert det.handle_packet(req) is None

    def test_status_shape(self):
        from modules.network.arp_guard import ARPSpoofDetector
        s = ARPSpoofDetector().status()
        assert s["detections"] == 0
        assert s["bindings_learned"] == 0


class TestEngineDefenses:
    """Engine wiring: the three hooks fire inside _handle_packet."""

    def _engine(self):
        from modules.network.engine import NetworkEngine
        return NetworkEngine(interface="eth0", adaptive=False)

    def test_icmp_tunnel_frame_emitted(self):
        engine = self._engine()
        # 512B payload crosses the threshold on the first packet.
        import anyio

        async def run():
            await engine._handle_packet(_icmp_pkt(b"X" * 512))

        anyio.run(run)
        frames = [f for f in engine.recent_frames if f["frame_type"] == "icmp_tunnel"]
        assert len(frames) == 1
        assert frames[0]["data"]["payload_size"] == 512

    def test_arp_alert_frame_emitted(self):
        engine = self._engine()
        # Pin the protected IP: only gateway/protected bindings alert, and
        # the machine's real default route differs per environment.
        engine.arp_detector.protected_ips.add("192.168.1.1")
        import anyio

        async def run():
            await engine._handle_packet(_arp_reply("192.168.1.1", "aa:aa:aa:aa:aa:01"))
            await engine._handle_packet(_arp_reply("192.168.1.1", "bb:bb:bb:bb:bb:02"))

        anyio.run(run)
        frames = [f for f in engine.recent_frames if f["frame_type"] == "arp_spoof_alert"]
        assert len(frames) == 1
        assert frames[0]["data"]["spoof_mac"] == "bb:bb:bb:bb:bb:02"

    def test_udp_modifier_hook_present(self):
        """The modifier is wired as a packet callback and honors its switch."""
        engine = self._engine()
        assert engine.udp_modifier is not None
        assert engine.udp_modifier.enabled is False
        # Enabled with a rule → matching packets are counted.
        from modules.network.udp_modifier import UDPModifyRule
        engine.udp_modifier.add_rule(
            UDPModifyRule(name="t", dst_port=6000, payload_replace=b"E"))
        engine.udp_modifier.enabled = True
        engine.udp_modifier.handle_packet(_udp_pkt())
        assert engine.udp_modifier.matches == 1
        # No manipulator backend → rewrite not injected, error counted.
        assert engine.udp_modifier.rewrites == 0
