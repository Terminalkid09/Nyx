"""TCP/UDP stream reconstruction - pure Python."""
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from core.network.capture import RawPacket
from core.network.protocols.base import FiveTuple, TCPStream, UDPFlow

logger = logging.getLogger(__name__)


@dataclass
class TCPFrame:
    """Single TCP frame in a stream."""
    seq_start: int
    seq_end: int
    payload: bytes
    flags: int
    timestamp: datetime
    is_client: bool


@dataclass
class UDPPacket:
    """Single UDP payload chunk in a flow."""
    payload: bytes
    timestamp: datetime
    length: int


@dataclass
class TCPSegment:
    """TCP segment for reassembly."""
    seq: int
    data: bytes
    flags: int
    timestamp: datetime


class TCPReassembler:
    """TCP stream reassembler with out-of-order handling."""

    def __init__(self, max_gap: int = 65535, timeout: float = 300.0):
        self.max_gap = max_gap
        self.timeout = timedelta(seconds=timeout)
        self._streams: dict[FiveTuple, TCPStream] = {}
        self._pending: dict[FiveTuple, list[TCPSegment]] = defaultdict(list)
        self._client_ports: set[int] = set()

    def feed(self, pkt: RawPacket) -> list[TCPStream]:
        """Feed a raw packet, return the stream it belongs to (if any)."""
        stream = self._process_packet(pkt)
        return [stream] if stream else []

    def get_stream(self, five_tuple: FiveTuple) -> Optional[TCPStream]:
        return self._streams.get(five_tuple)

    def get_all_streams(self) -> list[TCPStream]:
        return list(self._streams.values())

    def _process_packet(self, pkt: RawPacket) -> Optional[TCPStream]:
        try:
            from scapy.all import IP, TCP
            ip = IP(pkt.raw_bytes)
            if TCP not in ip:
                return None

            tcp = ip[TCP]
            five_tuple = FiveTuple(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                protocol=6
            )

            reverse = five_tuple.reverse()
            stream = self._streams.get(five_tuple) or self._streams.get(reverse)

            if not stream:
                stream = TCPStream(five_tuple=five_tuple)
                stream.start_time = pkt.timestamp
                self._streams[five_tuple] = stream
                self._client_ports.add(tcp.sport)

            is_client = tcp.sport in self._client_ports

            if stream.client_isn is None and (tcp.flags & 0x02):
                if is_client:
                    stream.client_isn = tcp.seq
                else:
                    stream.server_isn = tcp.seq

            if tcp.flags & 0x10:
                if is_client:
                    stream.client_window_scale = (tcp.window >> 14) & 0xF
                else:
                    stream.server_window_scale = (tcp.window >> 14) & 0xF

            payload = bytes(tcp.payload)
            if payload:
                segment = TCPSegment(
                    seq=tcp.seq,
                    data=payload,
                    flags=tcp.flags,
                    timestamp=pkt.timestamp
                )
                self._add_segment(stream, segment, is_client)

            stream.last_seen = pkt.timestamp
            self._cleanup_old_streams(pkt.timestamp)
            return stream

        except Exception as e:
            logger.debug("TCP reassembly error: %s", e)
            return None

    def _add_segment(self, stream: TCPStream, segment: TCPSegment, is_client: bool):
        """Merge a segment into the ordered pending list with overlap/gap handling.

        Overlapping bytes are resolved by keeping the data from the segment with
        the most recent timestamp.
        """
        key = stream.five_tuple
        pending = self._pending[key]
        pending.append(segment)
        pending.sort(key=lambda s: s.seq)

        merged = []
        for seg in pending:
            if not merged:
                merged.append(seg)
                continue
            last = merged[-1]
            last_end = last.seq + len(last.data)
            seg_end = seg.seq + len(seg.data)

            if seg.seq > last_end:
                # Discontiguous data — keep as separate segment (gap recorded).
                merged.append(seg)
            elif seg_end > last_end:
                # Overlapping tail: keep the newer timestamp's bytes for the
                # overlap region, append the non-overlapping remainder.
                overlap = last_end - seg.seq
                tail = seg.data[overlap:] if overlap > 0 else seg.data
                if overlap > 0 and seg.timestamp >= last.timestamp:
                    # Newer segment rewrites the overlap region.
                    last.data = last.data[: max(0, overlap)] + seg.data[overlap:]
                else:
                    last.data += tail
                last.timestamp = seg.timestamp if seg.timestamp >= last.timestamp else last.timestamp
            # else: fully contained — drop the duplicate (newer timestamps win
            # only for the tail case above; full duplicates are redundant).

        self._pending[key] = merged
        self._emit_frames(stream, segment, is_client)

    def _emit_frames(self, stream: TCPStream, segment: TCPSegment, is_client: bool):
        """Append a TCPFrame for the incoming segment, skipping pure retransmissions.

        Frames are appended in chronological arrival order so decoders that
        accumulate buffers (HTTP, DNS-over-TCP) see data in order. Segments
        already fully covered by an earlier frame (retransmissions) are dropped.
        """
        if not segment.data:
            return
        for f in reversed(stream.frames):
            if f.is_client == is_client and \
               f.seq_start <= segment.seq and \
               f.seq_end >= segment.seq + len(segment.data):
                return
        stream.frames.append(TCPFrame(
            seq_start=segment.seq,
            seq_end=segment.seq + len(segment.data),
            payload=segment.data,
            flags=segment.flags,
            timestamp=segment.timestamp,
            is_client=is_client,
        ))

    def _cleanup_old_streams(self, now: datetime):
        to_remove = []
        for key, stream in self._streams.items():
            if stream.last_seen and now - stream.last_seen > self.timeout:
                to_remove.append(key)
        for key in to_remove:
            del self._streams[key]
            if key in self._pending:
                del self._pending[key]


class UDPFlowTracker:
    """UDP flow tracker with IP fragmentation reassembly."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timedelta(seconds=timeout)
        self._flows: dict[FiveTuple, UDPFlow] = {}
        self._fragments: dict[tuple, dict] = defaultdict(dict)

    def feed(self, pkt: RawPacket) -> Optional[UDPFlow]:
        try:
            from scapy.all import IP, UDP
            ip = IP(pkt.raw_bytes)
            if UDP not in ip:
                return None

            udp = ip[UDP]
            five_tuple = FiveTuple(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=udp.sport,
                dst_port=udp.dport,
                protocol=17
            )

            flow = self._flows.get(five_tuple)
            if not flow:
                flow = UDPFlow(five_tuple=five_tuple)
                flow.start_time = pkt.timestamp
                self._flows[five_tuple] = flow

            payload = self._reassemble_fragments(ip, udp, pkt.timestamp, five_tuple)
            if payload is None:
                # Still a fragment of a bigger datagram — nothing complete yet.
                flow.last_seen = pkt.timestamp
                self._cleanup_old_flows(pkt.timestamp)
                return flow

            flow.packets.append(UDPPacket(
                payload=payload,
                timestamp=pkt.timestamp,
                length=len(payload)
            ))
            flow.last_seen = pkt.timestamp

            self._cleanup_old_flows(pkt.timestamp)
            return flow

        except Exception as e:
            logger.debug("UDP flow tracking error: %s", e)
            return None

    def _reassemble_fragments(self, ip, udp, timestamp: datetime, five_tuple) -> Optional[bytes]:
        """Reassemble IP-fragmented UDP payloads.

        Returns the complete payload when the datagram is complete (or was never
        fragmented), otherwise None (waiting for more fragments).
        """
        try:
            frag_offset = ip.frag * 8
            more_fragments = bool(ip.flags & 0x1)
        except Exception:
            frag_offset = 0
            more_fragments = False

        if frag_offset == 0 and not more_fragments:
            # Not fragmented — return payload as-is.
            return bytes(udp.payload)

        key = (five_tuple, ip.id)
        self._fragments[key]["chunks"] = self._fragments[key].get("chunks", {})
        self._fragments[key]["last"] = max(self._fragments[key].get("last", 0), frag_offset + len(bytes(udp.payload)))
        self._fragments[key]["seen_offsets"] = self._fragments[key].get("seen_offsets", set())
        self._fragments[key]["seen_offsets"].add(frag_offset)
        self._fragments[key]["chunks"][frag_offset] = bytes(udp.payload)
        self._fragments[key]["timestamp"] = timestamp

        if more_fragments:
            return None

        # Last fragment received — check completeness.
        data = self._fragments[key]["chunks"]
        offsets = sorted(data.keys())
        expected = 0
        for off in offsets:
            if off != expected:
                return None
            expected = off + len(data[off])

        payload = b"".join(data[o] for o in offsets)
        del self._fragments[key]
        return payload

    def get_flow(self, five_tuple: FiveTuple) -> Optional[UDPFlow]:
        return self._flows.get(five_tuple)

    def get_all_flows(self) -> list[UDPFlow]:
        return list(self._flows.values())

    def _cleanup_old_flows(self, now: datetime):
        to_remove = []
        for key, flow in self._flows.items():
            if flow.last_seen and now - flow.last_seen > self.timeout:
                to_remove.append(key)
        for key in to_remove:
            del self._flows[key]

        for fkey in list(self._fragments.keys()):
            if self._fragments[fkey].get("timestamp") and \
               now - self._fragments[fkey]["timestamp"] > self.timeout:
                del self._fragments[fkey]