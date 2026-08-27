"""Tests for the network layer (capture, reassembly, scapy adapters, pcap, stats)."""
import asyncio
import struct
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from core.network.capture import RawPacket
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
