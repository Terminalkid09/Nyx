"""NetworkEngine - high-level orchestration for network capture and analysis.

The engine owns the capture loop and the decode pipeline:
  RawPacket -> packet-level decoders (ARP/ICMP, via scapy)
            -> TCP reassembly -> stream decoders (DNS-over-TCP)
            -> UDP tracking  -> flow decoders (DNS/DHCP/QUIC, via scapy)
            -> TLS SNI label (metadata only — parsing stays with mitmproxy)

Every packet and every protocol frame is buffered (bounded) for the API/UI
and published on the event bus / pushed to registered callbacks (WebSocket).
"""
import asyncio
import logging
from collections import deque
from datetime import datetime
from typing import Any, Callable, List, Optional

from core.network.capture import PacketCapture, RawPacket
from core.network.manipulate import PacketManipulator
from core.network.reassemble import TCPReassembler, UDPFlowTracker, TCPStream
from core.network.protocols import load_all_decoders, ProtocolDecoder, ProtocolFrame
from core.network.protocols.base import FiveTuple
from core.network.pcap import PCAPWriter
from core.network.stats import StatsCollector
from core.events.bus import EventBus
from modules.network.mitm_integration import extract_sni_from_stream

logger = logging.getLogger(__name__)

_TLS_PORTS = (443, 8443, 9443, 993, 995, 5223, 8883)


def _ft_dict(ft: FiveTuple) -> dict:
    return {
        "src_ip": ft.src_ip,
        "dst_ip": ft.dst_ip,
        "src_port": ft.src_port,
        "dst_port": ft.dst_port,
        "protocol": ft.protocol,
    }


class NetworkEngine:
    """High-level network capture and analysis engine."""

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "tcp or udp",
        snaplen: int = 65535,
        promisc: bool = True,
        event_bus: Optional[EventBus] = None,
        max_packets: int = 1000,
        max_frames: int = 500,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_path: Optional[str] = None
        self._pcap_writer: Optional[PCAPWriter] = None

        self.capture = PacketCapture(interface, bpf_filter, snaplen, promisc)
        self.manipulator = PacketManipulator(interface)
        self.tcp_reassembler = TCPReassembler()
        self.udp_tracker = UDPFlowTracker()
        self.decoders: List[ProtocolDecoder] = load_all_decoders()
        self.stats_collector = StatsCollector()
        self._event_bus = event_bus

        self._running = False
        self._capture_task: Optional[asyncio.Task] = None
        self._packet_callbacks: List[Callable[[RawPacket], Any]] = []
        self._frame_callbacks: List[Callable[[dict], Any]] = []
        self._stream_callbacks: List[Callable[[TCPStream], Any]] = []

        # Bounded buffers served to the API/UI ("packet list" + "frame list").
        self.recent_packets: deque = deque(maxlen=max_packets)
        self.recent_frames: deque = deque(maxlen=max_frames)
        # Raw packets (same window) kept for .pcap export.
        self.recent_raw_packets: deque = deque(maxlen=max_packets)

    # ── configuration / wiring ────────────────────────────────────────────

    def set_pcap_output(self, writer: PCAPWriter) -> None:
        self._pcap_writer = writer
        self.pcap_path = writer.path

    def on_packet(self, callback: Callable[[RawPacket], Any]) -> None:
        self._packet_callbacks.append(callback)

    def on_frame(self, callback: Callable[[dict], Any]) -> None:
        self._frame_callbacks.append(callback)

    def on_stream(self, callback: Callable[[TCPStream], Any]) -> None:
        self._stream_callbacks.append(callback)

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self.capture.start()
        self._running = True
        logger.info("NetworkEngine started on %s (BPF: %r)", self.interface, self.bpf_filter)

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self.capture.stop()
        self.manipulator.stop()

        if self._pcap_writer:
            self._pcap_writer.close()
            self._pcap_writer = None

        logger.info("NetworkEngine stopped")

    async def run_async(self) -> None:
        """Run the capture loop asynchronously.

        capture.packets() yields while the sniffer is running AND drains the
        remaining queue after stop(), so the inner loop naturally terminates;
        the outer loop only re-checks the running flag.
        """
        while self._running:
            try:
                for pkt in self.capture.packets():
                    if not self._running:
                        break
                    await self._handle_packet(pkt)
                    await asyncio.sleep(0)
                await asyncio.sleep(0.05)
            except Exception as e:
                logger.debug("Capture loop error: %s", e)
                await asyncio.sleep(0.1)

    # ── packet pipeline ───────────────────────────────────────────────────

    async def _handle_packet(self, pkt: RawPacket) -> None:
        summary = self._summarize(pkt)

        if self._pcap_writer:
            self._pcap_writer.write_packet(pkt)

        self.stats_collector.record_packet(
            pkt,
            protocol=summary.get("proto", "other"),
            port=summary.get("dport", 0) or summary.get("sport", 0),
        )

        self.recent_packets.append(summary)
        self.recent_raw_packets.append(pkt)

        for cb in self._packet_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(pkt)
                else:
                    cb(pkt)
            except Exception as e:
                logger.debug("Packet callback error: %s", e)

        # Packet-level decoders (ARP/ICMP — no TCP/UDP stream to track).
        for decoder in self.decoders:
            try:
                if not decoder.can_decode_packet(pkt):
                    continue
                for frame in decoder.decode_packet(pkt):
                    await self._emit_frame(frame)
            except Exception as e:
                logger.debug("Packet decoder error (%s): %s", decoder.name, e)

        # TCP streams -> stream decoders.
        streams = self.tcp_reassembler.feed(pkt)
        for stream in streams:
            await self._handle_stream(stream)
            for cb in self._stream_callbacks:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(stream)
                    else:
                        cb(stream)
                except Exception as e:
                    logger.debug("Stream callback error: %s", e)

        # UDP flows -> flow decoders.
        flow = self.udp_tracker.feed(pkt)
        if flow:
            await self._handle_flow(flow)

        if self._event_bus:
            await self._event_bus.publish({"type": "network.packet", "data": summary})

    async def _handle_stream(self, stream: TCPStream) -> None:
        # TLS SNI label — metadata only, full TLS/HTTP parsing is mitmproxy's.
        if not stream.metadata.get("sni") and stream.five_tuple.dst_port in _TLS_PORTS:
            sni = extract_sni_from_stream(stream)
            if sni:
                stream.metadata["sni"] = sni
                await self._emit_frame(ProtocolFrame(
                    frame_type="tls",
                    timestamp=stream.last_seen or stream.start_time or datetime.now(),
                    data={"sni": sni, "note": "TLS handled by mitmproxy"},
                    raw_ref=b"",
                    five_tuple=stream.five_tuple,
                ))

        for decoder in self.decoders:
            try:
                if not decoder.can_decode(stream):
                    continue
            except Exception as e:
                logger.debug("Decoder can_decode error (%s): %s", decoder.name, e)
                continue
            try:
                for frame in decoder.decode(stream):
                    await self._emit_frame(frame)
            except Exception as e:
                logger.debug("Decoder error (%s): %s", decoder.name, e)

    async def _handle_flow(self, flow) -> None:
        for decoder in self.decoders:
            try:
                if not decoder.can_decode(flow):
                    continue
            except Exception as e:
                logger.debug("Decoder can_decode error (%s): %s", decoder.name, e)
                continue
            try:
                for frame in decoder.decode(flow):
                    await self._emit_frame(frame)
            except Exception as e:
                logger.debug("Decoder error (%s): %s", decoder.name, e)

    async def _emit_frame(self, frame: ProtocolFrame) -> None:
        if frame is None:
            return
        data = {
            "frame_type": frame.frame_type,
            "timestamp": frame.timestamp.isoformat(),
            "data": frame.data,
            "five_tuple": _ft_dict(frame.five_tuple) if frame.five_tuple else None,
        }
        self.recent_frames.append(data)
        for cb in self._frame_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(data)
                else:
                    cb(data)
            except Exception as e:
                logger.debug("Frame callback error: %s", e)
        if self._event_bus:
            await self._event_bus.publish({"type": "network.frame", "data": data})

    @staticmethod
    def _summarize(pkt: RawPacket) -> dict:
        """Lightweight scapy dissect -> JSON-safe packet summary."""
        base = {
            "timestamp": pkt.timestamp.isoformat(),
            "length": len(pkt.raw_bytes),
            "proto": "other",
        }
        try:
            from scapy.all import ARP, ICMP, IP, IPv6, TCP, UDP, Ether
            from core.network.reassemble import _ip_layer
            eth = Ether(pkt.raw_bytes)

            if ARP in eth:
                base["proto"] = "arp"
                base["eth_src"] = eth.src
                base["eth_dst"] = eth.dst
                base["src"] = eth[ARP].psrc
                base["dst"] = eth[ARP].pdst
                return base

            ip = eth.getlayer(IP) or eth.getlayer(IPv6)
            if ip is None:
                # Bare IP datagram (no L2 header) — synthetic/injected packets.
                ip = _ip_layer(pkt.raw_bytes)
                if ip is None:
                    return base
            else:
                base["eth_src"] = eth.src
                base["eth_dst"] = eth.dst
            base["src"] = ip.src
            base["dst"] = ip.dst

            if TCP in eth:
                base["proto"] = "tcp"
                base["sport"] = eth[TCP].sport
                base["dport"] = eth[TCP].dport
            elif UDP in eth:
                base["proto"] = "udp"
                base["sport"] = eth[UDP].sport
                base["dport"] = eth[UDP].dport
            elif ICMP in eth:
                base["proto"] = "icmp"
                base["icmp_type"] = int(eth[ICMP].type)
            else:
                base["proto"] = "ip"
        except Exception as e:
            logger.debug("Packet summarize error: %s", e)
        return base

    # ── stats / queries ───────────────────────────────────────────────────

    def get_stats(self):
        return self.stats_collector.get_stats(
            len(self.tcp_reassembler.get_all_streams()),
            len(self.udp_tracker.get_all_flows())
        )

    def get_packet_list(self, limit: int = 200) -> list[dict]:
        items = list(self.recent_packets)
        return items[-limit:]

    def get_frame_list(self, limit: int = 200) -> list[dict]:
        items = list(self.recent_frames)
        return items[-limit:]

    def get_raw_packets(self, limit: int = 500) -> list[RawPacket]:
        items = list(self.recent_raw_packets)
        return items[-limit:]
