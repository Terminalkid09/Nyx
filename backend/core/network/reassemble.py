"""TCP/UDP stream reconstruction - pure Python."""
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from core.network.capture import RawPacket
from core.network.protocols.base import FiveTuple, TCPStream, UDPFlow

logger = logging.getLogger(__name__)


def _ip_layer(raw: bytes):
    """Return the IP/IPv6 layer of a raw packet.

    The capture produces layer-2 frames (Ethernet), but tests and injected/
    synthetic packets may be bare IP datagrams — so try dissecting from L2
    first, then fall back to parsing the bytes as a plain IP header.
    """
    try:
        from scapy.all import Ether, IP, IPv6
        eth = Ether(raw)
        ip = eth.getlayer(IP) or eth.getlayer(IPv6)
        if ip is not None:
            return ip
    except Exception:
        pass
    try:
        if not raw:
            return None
        version = raw[0] >> 4
        from scapy.all import IP, IPv6
        if version == 4:
            return IP(raw)
        if version == 6:
            return IPv6(raw)
    except Exception:
        pass
    return None


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
        self._out_of_order: dict[tuple, list[TCPSegment]] = defaultdict(list)
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
            from scapy.all import TCP
            ip = _ip_layer(pkt.raw_bytes)
            if ip is None or TCP not in ip:
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

            # Window scale is NOT encoded in the TCP window field — it is a
            # TCP option (kind 3, WScale) negotiated in the SYN/SYN-ACK
            # exchange. Reading it out of the window field produced garbage.
            if tcp.flags & 0x02:
                for opt_name, opt_val in tcp.options:
                    if opt_name == "WScale":
                        try:
                            scale = int(opt_val)
                        except (TypeError, ValueError):
                            scale = 0
                        if is_client:
                            stream.client_window_scale = scale
                        else:
                            stream.server_window_scale = scale
                        break

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

        # Snapshot the incoming segment BEFORE merging: the merge mutates the
        # shared segment objects in place (pending/merged), so the frame
        # emission must use a copy of the original bytes, not the merged tail.
        incoming = TCPSegment(
            seq=segment.seq,
            data=bytes(segment.data),
            flags=segment.flags,
            timestamp=segment.timestamp,
        )

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
                # Overlapping tail. The overlap region is the LAST `overlap`
                # bytes of last.data — last may already span far past seg.seq,
                # so slicing last.data[:overlap] (the old code) grabbed the
                # wrong bytes whenever the buffer was longer than the overlap.
                overlap = last_end - seg.seq
                if overlap > 0 and seg.timestamp >= last.timestamp:
                    # Newer segment rewrites the overlapped tail.
                    last.data = last.data[:-overlap] + seg.data[overlap:]
                else:
                    # Older (or adjacent) segment: keep the existing overlap
                    # bytes, append only the non-overlapping remainder.
                    last.data += seg.data[overlap:]
                last.timestamp = seg.timestamp if seg.timestamp >= last.timestamp else last.timestamp
            # else: fully contained — drop the duplicate (full retransmissions
            # carry identical bytes and add nothing).

        self._pending[key] = merged
        self._emit_frames(stream, incoming, is_client)

    def _emit_frames(self, stream: TCPStream, segment: TCPSegment, is_client: bool):
        """Append a TCPFrame for the incoming segment, keeping each direction's
        frames in strictly contiguous sequence order.

        Previously frames were appended in arrival order, so an out-of-order
        segment (or joining mid-stream) gave decoders and the UI a sequence
        that jumped backwards. Now: retransmissions (fully covered by the last
        frame of the direction) are dropped, gaps are buffered until filled,
        and data arriving before the current anchor is inserted in order.
        """
        if not segment.data:
            return
        seg_start = segment.seq
        seg_end = segment.seq + len(segment.data)

        last = self._last_frame(stream, is_client)

        # Fully covered by the previous frame -> pure retransmission, drop it.
        if last is not None and last.seq_start <= seg_start and last.seq_end >= seg_end:
            return

        if last is None or seg_start == last.seq_end:
            # First frame of the direction, or perfectly contiguous.
            self._append_frame(stream, segment, is_client)
            self._flush_out_of_order(stream, is_client)
            return

        if seg_start > last.seq_end:
            # Gap in the sequence — hold until the missing bytes arrive.
            self._out_of_order[(stream.five_tuple, is_client)].append(segment)
            return

        if seg_end <= last.seq_start:
            # Data entirely before the current anchor (we joined mid-stream or
            # a segment arrived late): insert in order, not after it.
            self._insert_before_direction(stream, segment, is_client)
            self._flush_out_of_order(stream, is_client)
            return

        # Overlaps the tail of the last frame but extends past it
        # (e.g. [1005:1015] arriving after [1000:1010]) — emit only the
        # uncovered part so the sequence stays contiguous.
        if seg_end > last.seq_end:
            uncovered = segment.data[last.seq_end - seg_start:]
            self._append_frame(
                stream,
                TCPSegment(seq=last.seq_end, data=uncovered,
                           flags=segment.flags, timestamp=segment.timestamp),
                is_client,
            )
            self._flush_out_of_order(stream, is_client)

    def _last_frame(self, stream: TCPStream, is_client: bool) -> Optional[TCPFrame]:
        for f in reversed(stream.frames):
            if f.is_client == is_client:
                return f
        return None

    def _append_frame(self, stream: TCPStream, segment: TCPSegment, is_client: bool):
        stream.frames.append(TCPFrame(
            seq_start=segment.seq,
            seq_end=segment.seq + len(segment.data),
            payload=segment.data,
            flags=segment.flags,
            timestamp=segment.timestamp,
            is_client=is_client,
        ))

    def _insert_before_direction(self, stream: TCPStream, segment: TCPSegment, is_client: bool):
        frame = TCPFrame(
            seq_start=segment.seq,
            seq_end=segment.seq + len(segment.data),
            payload=segment.data,
            flags=segment.flags,
            timestamp=segment.timestamp,
            is_client=is_client,
        )
        for idx, f in enumerate(stream.frames):
            if f.is_client == is_client:
                stream.frames.insert(idx, frame)
                return
        stream.frames.append(frame)

    def _flush_out_of_order(self, stream: TCPStream, is_client: bool):
        key = (stream.five_tuple, is_client)
        buf = self._out_of_order.get(key)
        if not buf:
            return
        last = self._last_frame(stream, is_client)
        if last is None:
            return
        progress = True
        while progress:
            progress = False
            for seg in list(buf):
                if seg.seq == last.seq_end:
                    self._append_frame(stream, seg, is_client)
                    buf.remove(seg)
                    last = stream.frames[-1]
                    progress = True
                    break
        if not buf:
            del self._out_of_order[key]

    def _cleanup_old_streams(self, now: datetime):
        to_remove = []
        for key, stream in self._streams.items():
            if stream.last_seen and now - stream.last_seen > self.timeout:
                to_remove.append(key)
        for key in to_remove:
            del self._streams[key]
            if key in self._pending:
                del self._pending[key]
            # Drop any buffered out-of-order segments for both directions.
            for side in (True, False):
                buf_key = (key, side)
                if buf_key in self._out_of_order:
                    del self._out_of_order[buf_key]


class UDPFlowTracker:
    """UDP flow tracker with IP fragmentation reassembly."""

    def __init__(self, timeout: float = 60.0):
        self.timeout = timedelta(seconds=timeout)
        self._flows: dict[FiveTuple, UDPFlow] = {}
        self._fragments: dict[tuple, dict] = defaultdict(dict)

    def feed(self, pkt: RawPacket) -> Optional[UDPFlow]:
        try:
            from scapy.all import UDP
            ip = _ip_layer(pkt.raw_bytes)
            if ip is None or UDP not in ip:
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