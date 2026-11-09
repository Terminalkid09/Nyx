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
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from core.network.capture import PacketCapture, RawPacket, resolve_active_interface
from core.network.manipulate import PacketManipulator
from core.network.reassemble import TCPReassembler, UDPFlowTracker, TCPStream
from core.network.protocols import load_all_decoders, ProtocolDecoder, ProtocolFrame
from core.network.protocols.quic import QUICDecoder
from core.network.protocols.base import FiveTuple
from core.network.pcap import PCAPWriter
from core.network.stats import StatsCollector
from core.events.bus import EventBus
from modules.network.mitm_integration import extract_sni_from_stream
from modules.network.udp_modifier import UDPModifier
from modules.network.icmp_detector import ICMPTunnelDetector
from modules.network.arp_guard import ARPSpoofDetector

logger = logging.getLogger(__name__)

_TLS_PORTS = (443, 8443, 9443, 993, 995, 5223, 8883)


class _ScapyDNSWarningFilter(logging.Filter):
    """Drop scapy's cosmetic "DNS decompression loop detected" warnings.

    scapy (scapy/layers/dns.py) fires these when a DNS name's compression-
    pointer chain loops — typical of truncated/malformed UDP DNS on port 53.
    It already recovers gracefully (breaks and returns the partial name), so
    the messages are noise, not errors. We filter ONLY these records on the
    scapy.runtime logger so we keep genuine warnings (e.g. "No libpcap
    provider available") visible.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        return "DNS decompression loop" not in record.getMessage()


# Idempotent: attaching the same filter twice would be harmless but let's
# only register it once (guard against re-imports / repeated engine loads).
if not any(
    isinstance(f, _ScapyDNSWarningFilter)
    for f in logging.getLogger("scapy.runtime").filters
):
    logging.getLogger("scapy.runtime").addFilter(_ScapyDNSWarningFilter())


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
        bpf_filter: str = "tcp or udp or arp or icmp",
        snaplen: int = 65535,
        promisc: bool = True,
        event_bus: Optional[EventBus] = None,
        max_packets: int = 1000,
        max_frames: int = 500,
        stats_collector: Optional[StatsCollector] = None,
        adaptive: bool = True,
    ):
        # ``interface`` may be "auto" — resolved to the live default-route
        # interface in start(). Kept verbatim until then so /status can show
        # what was requested vs what got picked.
        self.requested_interface = interface
        self.interface = interface
        self.adaptive = adaptive
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self._watchdog_task: Optional[asyncio.Task] = None
        self._interface_changes = 0
        # Monotonic per-packet id (stable key for GET /packets/{seq} detail).
        self._packet_seq = 0
        # Watchdog tuning (instance attrs so tests can shorten them).
        self._watchdog_interval = 5.0      # seconds between polls
        self._watchdog_debounce = 2        # consecutive differing polls
        self.pcap_path: Optional[str] = None
        self._pcap_writer: Optional[PCAPWriter] = None

        self.capture = PacketCapture(interface, bpf_filter, snaplen, promisc)
        self.manipulator = PacketManipulator(interface)
        self.tcp_reassembler = TCPReassembler()
        self.udp_tracker = UDPFlowTracker()
        self.decoders: List[ProtocolDecoder] = load_all_decoders()
        self.stats_collector = stats_collector or StatsCollector()
        self._event_bus = event_bus

        # Active/passive network-layer defenses & tooling (wired after the
        # callback lists exist — see below in __init__).

        self._running = False
        self._capture_task: Optional[asyncio.Task] = None
        self._packet_callbacks: List[Callable[[RawPacket], Any]] = []
        self._frame_callbacks: List[Callable[[dict], Any]] = []
        self._stream_callbacks: List[Callable[[TCPStream], Any]] = []

        # Active/passive network-layer defenses & tooling (after the callback
        # lists exist):
        #  - UDPModifier: rule-driven in-flight UDP rewrites (re-injected via
        #    the PacketManipulator). Off until rules are added + enabled.
        #    Registered as a packet callback (fire-and-forget, no frames).
        #  - ICMPTunnelDetector / ARPSpoofDetector: passive analyzers invoked
        #    DIRECTLY in _handle_packet (NOT as callbacks) because their
        #    return value produces icmp_tunnel / arp_spoof_alert frames —
        #    double registration would consume the detection silently.
        self.udp_modifier = UDPModifier(manipulator=self.manipulator)
        self.icmp_detector = ICMPTunnelDetector()
        self.arp_detector = ARPSpoofDetector()
        self._packet_callbacks.append(self.udp_modifier.handle_packet)
        # Bounded buffers served to the API/UI ("packet list" + "frame list").
        self.recent_packets: deque = deque(maxlen=max_packets)
        self.recent_frames: deque = deque(maxlen=max_frames)
        # Raw packets (same window) kept for .pcap export.
        self.recent_raw_packets: deque = deque(maxlen=max_packets)
        # Signatures of already-emitted frames: decoders re-parse the whole
        # stream/flow on every packet (DNS/DHCP/QUIC re-decode ALL messages
        # seen so far), so without this every new packet would re-emit every
        # previous frame as a duplicate. Bounded deque, O(n) membership is
        # fine at this size.
        self._frame_signatures: deque = deque(maxlen=4000)
        # QUIC connection summaries (decoder aggregation): one live row per
        # QUIC connection (DCID) instead of one frame per datagram.
        self.quic_connections: Dict[str, dict] = {}
        # References to the summary dicts already sitting in recent_frames —
        # updated IN PLACE as counters grow, so the frame list holds exactly
        # one row per QUIC connection (no per-datagram spam).
        self._quic_frame_rows: Dict[str, dict] = {}
        # Per-stream decode checkpoints (absolute packet/frame count already
        # decoded) — decoders only process NEW payloads instead of re-parsing
        # the whole stream/flow on every packet (was O(n²) per flow).
        self._decode_checkpoints: Dict[str, int] = {}
        # Idle-eviction tuning (instance attrs so tests can shorten them).
        self.stream_idle_timeout = 600.0   # seconds of silence before eviction
        self.max_tracked_streams = 500     # hard cap, oldest-last_seen first
        self._last_sweep = datetime.now()

    @staticmethod
    def _ft_key(ft: FiveTuple) -> str:
        """Stable checkpoint/eviction key for a stream or flow."""
        return f"{ft.src_ip}|{ft.dst_ip}|{ft.src_port}|{ft.dst_port}|{ft.protocol}"

    # ── public counters ───────────────────────────────────────────────────

    @property
    def interface_changes(self) -> int:
        """Read-only rebind count for the API (/status ``interface_changes``).

        The route reads this exact attribute name — keep it in sync with the
        private ``_interface_changes`` counter the watchdog increments.
        """
        return self._interface_changes

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
        # Adaptive interface resolution: "auto" (or empty) binds to whatever
        # interface owns the default route right now. scapy's routing resync
        # + interface enumeration can take seconds on Windows (VPN adapters)
        # — always off the event loop, or every HTTP request (including
        # /capture/stop) freezes behind it.
        if str(self.requested_interface or "").strip().lower() in ("", "auto"):
            resolved = await asyncio.to_thread(resolve_active_interface, False)
            if resolved and resolved != self.interface:
                self.interface = resolved
                # Replace the not-yet-started capture with one bound to the
                # resolved name (safe: no sniffer thread exists yet).
                self.capture = PacketCapture(
                    self.interface, self.bpf_filter, self.snaplen, self.promisc
                )
        # AsyncSniffer construction does interface lookups — same reason, off
        # the loop (the sniffer itself runs in its own thread).
        await asyncio.to_thread(self.capture.start)
        self._running = True
        if self.adaptive and self._watchdog_task is None:
            self._watchdog_task = asyncio.create_task(self._interface_watchdog())
        logger.info("NetworkEngine started on %s (BPF: %r)", self.interface, self.bpf_filter)

    async def _interface_watchdog(self) -> None:
        """Rebind the sniffer when the active network interface changes.

        Polls the default-route interface every ``_watchdog_interval``
        seconds. A change is acted on only after ``_watchdog_debounce``
        consecutive differing polls (flaky Wi-Fi must not cause rebind
        storms). Only the capture rebinds — engine buffers, stats, tasks and
        the WS feed keep running; ~1-2s of packets may be lost in the gap.
        """
        current = self.interface
        pending: Optional[str] = None
        pending_count = 0
        while self._running:
            await asyncio.sleep(self._watchdog_interval)
            # BLOCKING resolve in a worker thread: on Windows a single
            # scapy/psutil enumeration can stall the loop for seconds, which
            # froze EVERY request (status polls, frames, and the Stop button
            # itself) every poll cycle.
            try:
                active = await asyncio.to_thread(resolve_active_interface, False)
            except Exception as e:
                logger.debug("Interface watchdog resolve error: %s", e)
                continue
            if not active or active == current:
                pending = None
                pending_count = 0
                continue
            if active == pending:
                pending_count += 1
            else:
                pending = active
                pending_count = 1
            if pending_count >= self._watchdog_debounce:
                await self._rebind_capture(active)
                current = active
                pending = None
                pending_count = 0

    async def _rebind_capture(self, new_interface: str) -> None:
        """Stop the sniffer and restart it on another interface."""
        old = self.interface
        try:
            await asyncio.to_thread(self.capture.stop)
        except Exception as e:
            logger.debug("Capture stop during rebind failed: %s", e)
        self.interface = new_interface
        self.capture = PacketCapture(
            new_interface, self.bpf_filter, self.snaplen, self.promisc
        )
        try:
            await asyncio.to_thread(self.capture.start)
            self._interface_changes += 1
            logger.info(
                "Active interface changed %s -> %s; capture rebound "
                "(%d change%s this session)",
                old, new_interface, self._interface_changes,
                "" if self._interface_changes == 1 else "s",
            )
        except Exception as e:
            logger.error("Capture rebind to %s failed: %s", new_interface, e)

    async def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._watchdog_task is not None:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
            self._watchdog_task = None
        # capture.stop() joins the sniffer thread (up to 5s) — never block the
        # event loop on shutdown, offload it to a worker thread.
        await asyncio.to_thread(self.capture.stop)
        await asyncio.to_thread(self.manipulator.stop)

        if self._pcap_writer:
            await asyncio.to_thread(self._pcap_writer.close)
            self._pcap_writer = None

        logger.info("NetworkEngine stopped")

    async def run_async(self) -> None:
        """Run the capture loop asynchronously.

        Drains via PacketCapture.next_packet_async(), which never blocks the
        event loop (get_nowait + sleep, unlike the old sync ``packets()``
        generator whose queue.get(timeout=0.2) froze the loop on every poll).
        Exits when capture is stopped and the queue is drained.
        """
        while True:
            pkt = await self.capture.next_packet_async()
            if pkt is None:
                break
            await self._handle_packet(pkt)
            await asyncio.sleep(0)

    # ── packet pipeline ───────────────────────────────────────────────────

    async def _handle_packet(self, pkt: RawPacket) -> None:
        summary = self._summarize(pkt)
        self._packet_seq += 1
        summary["seq"] = self._packet_seq

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

        # Passive ICMP-tunnel heuristic — emits an icmp_tunnel frame when a
        # flow's score crosses the threshold.
        detection = self.icmp_detector.handle_packet(pkt)
        if detection:
            await self._emit_frame(ProtocolFrame(
                frame_type="icmp_tunnel",
                timestamp=datetime.now(),
                data=detection,
                raw_ref=b"",
                five_tuple=None,
            ))

        # Third-party ARP-poisoning alert — emits an arp_spoof_alert frame.
        arp_alert = self.arp_detector.handle_packet(pkt)
        if arp_alert:
            await self._emit_frame(ProtocolFrame(
                frame_type="arp_spoof_alert",
                timestamp=datetime.now(),
                data=arp_alert,
                raw_ref=b"",
                five_tuple=None,
            ))

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

        # Bounded tables — cheap most ticks, sweeps every 30s.
        self._maybe_evict_idle()

        if self._event_bus:
            await self._event_bus.publish({"type": "network.packet", "data": summary})

    def _maybe_evict_idle(self) -> None:
        """Bound the stream/flow tables: drop entries idle for a long time and
        hard-cap the total (oldest-first). Keeps /streams cost and payload
        flat no matter how long a capture runs. Called at most once per
        sweep interval (30s), cost O(entries)."""
        now = datetime.now()
        if (now - self._last_sweep).total_seconds() < 30:
            return
        self._last_sweep = now

        idle = timedelta(seconds=self.stream_idle_timeout)
        for table in (self.tcp_reassembler._streams, self.udp_tracker._flows):
            # 1) Idle eviction.
            dead = [k for k, v in table.items()
                    if v.last_seen and (now - v.last_seen) > idle]
            for k in dead:
                self._decode_checkpoints.pop(self._ft_key(table[k].five_tuple), None)
                del table[k]
            # 2) Hard cap — evict oldest last_seen first.
            overflow = len(table) - self.max_tracked_streams
            if overflow > 0:
                oldest = sorted(
                    table.items(),
                    key=lambda kv: kv[1].last_seen or datetime.min,
                )[:overflow]
                for k, v in oldest:
                    self._decode_checkpoints.pop(self._ft_key(v.five_tuple), None)
                    del table[k]

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
            if isinstance(decoder, QUICDecoder):
                await self._handle_quic_flow(flow, decoder)
                continue
            key = self._ft_key(flow.five_tuple)
            start = self._decode_checkpoints.get(key, 0)
            try:
                new_frames = list(decoder.decode(flow, start=start))
            except Exception as e:
                logger.debug("Decoder error (%s): %s", decoder.name, e)
                continue
            self._decode_checkpoints[key] = flow.trimmed + len(flow.packets)
            for frame in new_frames:
                await self._emit_frame(frame)

    async def _handle_quic_flow(self, flow, decoder: QUICDecoder) -> None:
        """Aggregated QUIC: one live summary row per connection (DCID).

        decode(aggregate=True) returns one summary frame per connection seen
        in the flow. The FIRST summary for a connection is emitted as a frame
        row; later re-parses (every packet triggers a full flow re-decode)
        UPDATE the same row dict in place, so the frame list never grows per
        datagram. quic_connections always mirrors the latest counts for
        GET /api/network/quic and the status counter.
        """
        try:
            summaries = list(decoder.decode(flow, aggregate=True))
        except Exception as e:
            logger.debug("QUIC aggregate decode error: %s", e)
            return
        for frame in summaries:
            conn_id = frame.data.get("conn_id")
            if not conn_id:
                continue
            self.quic_connections[conn_id] = {
                "conn_id": conn_id,
                "dcid": frame.data.get("dcid"),
                "version": frame.data.get("version"),
                "packet_count": frame.data.get("packet_count", 0),
                "packet_types": frame.data.get("packet_types", {}),
                "first_seen": frame.timestamp.isoformat() if frame.timestamp else None,
                "last_seen": flow.last_seen.isoformat() if getattr(flow, "last_seen", None) else None,
                "five_tuple": _ft_dict(frame.five_tuple) if frame.five_tuple else None,
            }
            row = self._quic_frame_rows.get(conn_id)
            if row is None:
                await self._emit_frame(frame)
                if self.recent_frames and self.recent_frames[-1].get("frame_type") == "quic":
                    self._quic_frame_rows[conn_id] = self.recent_frames[-1]
            else:
                # Same object the UI/REST already saw — mutate, don't append.
                row["data"] = frame.data

    async def _emit_frame(self, frame: ProtocolFrame) -> None:
        if frame is None:
            return
        import json as _json
        sig = (
            frame.frame_type,
            frame.timestamp.isoformat(),
            _json.dumps(frame.data, sort_keys=True, default=str),
        )
        # Decoders re-parse the whole stream/flow on each packet — a frame
        # that was already emitted must not be pushed again (UI spam + WS
        # duplicates).
        if sig in self._frame_signatures:
            return
        self._frame_signatures.append(sig)

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

            # Dissect the transport layer from the RESOLVED ip layer, not from
            # eth: Ether() on a bare IP datagram (no L2 header) misparses the
            # IP header as an Ether header, so ``TCP in eth`` misses the ports.
            tcp = ip.getlayer(TCP)
            udp = ip.getlayer(UDP)
            icmp = ip.getlayer(ICMP)
            if tcp is not None:
                base["proto"] = "tcp"
                base["sport"] = tcp.sport
                base["dport"] = tcp.dport
            elif udp is not None:
                base["proto"] = "udp"
                base["sport"] = udp.sport
                base["dport"] = udp.dport
            elif icmp is not None:
                base["proto"] = "icmp"
                base["icmp_type"] = int(icmp.type)
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

    def get_packet_detail(self, seq: int) -> Optional[dict]:
        """Wireshark-style dissection of one buffered packet, by its seq id.

        ``recent_packets`` (summaries) and ``recent_raw_packets`` are appended
        in lockstep with the same maxlen, so a summary found N entries from
        the end maps to the raw packet N entries from the end. Returns None
        when the seq is not in the buffer (evicted or never seen).
        """
        items = list(self.recent_packets)
        raws = list(self.recent_raw_packets)
        for offset, summary in enumerate(reversed(items)):
            if summary.get("seq") == seq:
                if offset < len(raws):
                    return self._packet_detail(raws[-1 - offset], seq, summary)
                return None
        return None

    @staticmethod
    def _packet_detail(pkt: RawPacket, seq: int, summary: dict) -> dict:
        """Dissect one raw packet into a Wireshark-like layer tree.

        Walks the scapy layer chain (Ethernet -> IP -> TCP -> ...) and, for
        each layer, renders every declared field via the field's i2repr()
        — the same human-readable formatting Wireshark shows ("0x0800",
        IP strings, flag sets, ...). JSON-safe by construction: every value
        is coerced to str, ints kept raw for the UI to sort/display.
        """
        from scapy.all import Ether, IPv6, Packet  # noqa: F401 (Packet for typing)
        from core.network.reassemble import _ip_layer

        layers: list[dict] = []
        try:
            eth = Ether(pkt.raw_bytes)
            root = eth
            # Bare-IP datagrams (no L2 header): Ether misparses the IP
            # header — mirror _summarize's fallback.
            if eth.getlayer(IPv6) is None:
                from scapy.all import IP
                if eth.getlayer(IP) is None:
                    bare = _ip_layer(pkt.raw_bytes)
                    if bare is not None:
                        root = bare

            layer = root
            while layer is not None and layer.__class__.__name__ != "NoPayload":
                fields: dict = {}
                for f in layer.fields_desc:
                    name = f.name
                    try:
                        val = layer.getfieldval(name)
                        disp = f.i2repr(layer, val)
                    except Exception:
                        disp = str(getattr(layer, name, "?"))
                    entry: Any = disp if isinstance(disp, str) else str(disp)
                    try:
                        if isinstance(val, int) and not isinstance(val, bool):
                            entry = {"repr": entry, "raw": val}
                    except Exception:
                        pass
                    fields[name] = entry
                layers.append({
                    "name": layer.name or layer.__class__.__name__,
                    "fields": fields,
                })
                layer = layer.payload
        except Exception as e:
            layers.append({"name": "Error", "fields": {"dissect": str(e)}})

        hexdump_str = ""
        try:
            from scapy.utils import hexdump
            hexdump_str = hexdump(pkt.raw_bytes, dump=True)
        except Exception:
            pass

        return {
            "seq": seq,
            "timestamp": pkt.timestamp.isoformat(),
            "length": len(pkt.raw_bytes),
            "sniffed_on": pkt.interface,
            "proto": summary.get("proto", "other"),
            "layers": layers,
            "hexdump": hexdump_str,
        }
