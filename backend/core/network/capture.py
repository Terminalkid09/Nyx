"""Packet capture cross-platform interface.

The capture source is scapy's AsyncSniffer running in its own daemon thread —
the same layer-2 sniffing pattern dns_spoof.py already uses — so it works on
any platform where scapy + Npcap/libpcap is available. Every captured frame
is converted to a RawPacket (timestamp, raw_bytes, interface, metadata) and
queued for the async consumers (engine, PCAP writer, decoders).
"""
import asyncio
import logging
import queue
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


@dataclass
class RawPacket:
    """Raw packet with metadata."""
    timestamp: datetime
    raw_bytes: bytes
    interface: str
    metadata: dict = field(default_factory=dict)


@dataclass
class CaptureStats:
    """Capture statistics."""
    packets_received: int = 0
    packets_dropped: int = 0
    bytes_received: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None


class PacketCaptureBackend(ABC):
    """Abstract base for platform-specific capture backends."""

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def packets(self) -> Iterator[RawPacket]:
        pass

    @abstractmethod
    def stats(self) -> dict:
        pass


class PacketCapture:
    """Cross-platform packet capture built on scapy's AsyncSniffer.

    ``start()`` spawns the sniffer thread; captured frames are pushed to an
    internal bounded queue and drained via ``packets()`` / ``run_async()``.
    ``stop()`` sets the running flag so the sniffer exits promptly.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "",
        snaplen: int = 65535,
        promisc: bool = True
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promisc = promisc
        self._sniffer = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._packet_callbacks: list = []
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stats = {
            "packets_received": 0,
            "packets_dropped": 0,
            "bytes_received": 0,
            "errors": 0,
        }
        self._stats_lock = threading.Lock()
        self._start_time: Optional[datetime] = None

    def start(self) -> None:
        """Start the scapy sniffer (AsyncSniffer in a daemon thread)."""
        if self._running:
            return
        try:
            from scapy.all import AsyncSniffer, conf
            conf.verb = 0
        except Exception as e:
            logger.error("scapy unavailable for packet capture: %s", e)
            raise

        self._running = True
        self._start_time = datetime.now()

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface or None,   # None = all interfaces
                filter=self.bpf_filter or None,
                prn=self._on_scapy_packet,
                store=False,
                promisc=self.promisc,
                stop_filter=lambda _: not self._running,
            )
            self._sniffer.start()
        except Exception as e:
            self._running = False
            logger.error("Failed to start capture on %s: %s",
                         self.interface or "default", e)
            raise

        logger.info("Packet capture started on %s (BPF: %r)",
                    self.interface or "default", self.bpf_filter)

    def _on_scapy_packet(self, pkt) -> None:
        """scapy prn callback — runs in the sniffer thread."""
        if not self._running:
            return
        try:
            ts = getattr(pkt, "time", None)
            raw_pkt = RawPacket(
                timestamp=datetime.fromtimestamp(ts) if ts else datetime.now(),
                raw_bytes=bytes(pkt),
                interface=self.interface or getattr(pkt, "sniffed_on", "") or "",
                metadata={},
            )
            with self._stats_lock:
                self._stats["packets_received"] += 1
                self._stats["bytes_received"] += len(raw_pkt.raw_bytes)
            try:
                self._packet_queue.put(raw_pkt, timeout=0.5)
            except queue.Full:
                with self._stats_lock:
                    self._stats["packets_dropped"] += 1
        except Exception as e:
            with self._stats_lock:
                self._stats["errors"] += 1
            logger.debug("Capture handler error: %s", e)

    def stop(self) -> None:
        """Stop the sniffer and drain its thread."""
        if not self._running:
            return
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.debug("Sniffer stop error: %s", e)
            try:
                self._sniffer.join(timeout=5)
            except Exception:
                pass
            self._sniffer = None
        with self._stats_lock:
            received = self._stats["packets_received"]
            dropped = self._stats["packets_dropped"]
        logger.info("Packet capture stopped (received=%d dropped=%d)",
                    received, dropped)

    def packets(self) -> Iterator[RawPacket]:
        """Yield queued RawPackets until stopped and drained."""
        while self._running or not self._packet_queue.empty():
            try:
                yield self._packet_queue.get(timeout=0.2)
            except queue.Empty:
                continue

    def stats(self) -> CaptureStats:
        with self._stats_lock:
            s = dict(self._stats)
        return CaptureStats(
            packets_received=s["packets_received"],
            packets_dropped=s["packets_dropped"],
            bytes_received=s["bytes_received"],
            errors=s["errors"],
            start_time=self._start_time,
        )

    def on_packet(self, callback) -> None:
        """Register a callback invoked for each captured packet."""
        self._packet_callbacks.append(callback)

    async def run_async(self) -> None:
        """Run the capture loop asynchronously, calling callbacks."""
        while self._running or not self._packet_queue.empty():
            try:
                for pkt in self.packets():
                    if not self._running and self._packet_queue.empty():
                        break
                    for cb in self._packet_callbacks:
                        try:
                            if asyncio.iscoroutinefunction(cb):
                                await cb(pkt)
                            else:
                                cb(pkt)
                        except Exception as e:
                            logger.debug("Packet callback error: %s", e)
                    await asyncio.sleep(0)
            except Exception as e:
                logger.debug("Capture loop error: %s", e)
                await asyncio.sleep(0.1)
