"""Base protocol decoder interface."""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class FiveTuple:
    """5-tuple for flow identification."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def reverse(self) -> "FiveTuple":
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )


@dataclass
class ProtocolFrame:
    """Generic protocol frame - output of decoders."""
    frame_type: str
    timestamp: datetime
    data: dict
    raw_ref: bytes
    five_tuple: Optional[FiveTuple] = None
    metadata: dict = field(default_factory=dict)


@dataclass
class TCPStream:
    """Reconstructed TCP stream."""
    five_tuple: FiveTuple
    frames: list = field(default_factory=list)
    client_isn: Optional[int] = None
    server_isn: Optional[int] = None
    client_window_scale: int = 0
    server_window_scale: int = 0
    start_time: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: dict = field(default_factory=dict)
    # Incrementally maintained as frames are appended (O(1) per frame) so
    # stream listings never re-sum the whole frame list per request.
    bytes_total: int = 0


@dataclass
class UDPFlow:
    """UDP flow tracker."""
    five_tuple: FiveTuple
    packets: list = field(default_factory=list)
    start_time: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    # Incrementally maintained as packets are appended.
    bytes_total: int = 0
    # Number of oldest packets the tracker has trimmed to cap memory; decode
    # checkpoints must shift by this amount (see UDPFlowTracker.feed).
    trimmed: int = 0


class ProtocolDecoder(ABC):
    """Base interface for protocol decoders."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Decoder name (e.g., 'tls', 'http', 'dns')."""
        pass

    @property
    @abstractmethod
    def ports(self) -> Set[int]:
        """Hint ports for routing - not definitive."""
        pass

    @abstractmethod
    def can_decode(self, stream: TCPStream | UDPFlow) -> bool:
        """Check if this decoder can handle the stream."""
        pass

    @abstractmethod
    def decode(self, stream: TCPStream | UDPFlow, start: int = 0) -> Iterator[ProtocolFrame]:
        """Decode stream into protocol frames.

        ``start`` = absolute count of flow packets already decoded (the
        engine's per-stream checkpoint: stream.trimmed + local index).
        Decoders that track position decode only NEW payloads from local
        index ``start - stream.trimmed`` onward.
        """
        pass

    # ── Optional packet-level decoding ────────────────────────────────────
    # ARP and ICMP never appear in a TCP/UDP stream (no 5-tuple to track), so
    # decoders that work on raw packets implement these two instead of
    # can_decode/decode. Defaults keep stream-only decoders unaffected.

    def can_decode_packet(self, pkt: "RawPacket") -> bool:
        """Return True if this decoder can dissect the raw packet."""
        return False

    def decode_packet(self, pkt: "RawPacket") -> list[ProtocolFrame]:
        """Decode a raw packet into protocol frames (packet-level decoders)."""
        return []


class DecoderRegistry:
    """Registry for protocol decoders."""

    def __init__(self):
        self._decoders: list[ProtocolDecoder] = []

    def register(self, decoder: ProtocolDecoder) -> None:
        self._decoders.append(decoder)

    def get_decoders_for_stream(self, stream: TCPStream | UDPFlow) -> list[ProtocolDecoder]:
        return [d for d in self._decoders if d.can_decode(stream)]

    def get_all_decoders(self) -> list[ProtocolDecoder]:
        return self._decoders.copy()

    def clear(self) -> None:
        self._decoders.clear()


default_registry = DecoderRegistry()