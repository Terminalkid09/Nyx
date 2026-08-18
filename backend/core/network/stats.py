"""Live network statistics for UI."""
import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkStats:
    """Live network statistics."""
    pps: float = 0.0
    bps: float = 0.0
    active_flows: int = 0
    tcp_streams: int = 0
    udp_flows: int = 0
    bytes_total: int = 0
    packets_total: int = 0
    errors: int = 0
    by_protocol: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_port: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """JSON-serializable representation (plain dicts, ISO timestamps)."""
        return {
            "pps": self.pps,
            "bps": self.bps,
            "active_flows": self.active_flows,
            "tcp_streams": self.tcp_streams,
            "udp_flows": self.udp_flows,
            "bytes_total": self.bytes_total,
            "packets_total": self.packets_total,
            "errors": self.errors,
            "by_protocol": dict(self.by_protocol),
            "by_port": dict(self.by_port),
            "timestamp": self.timestamp.isoformat(),
        }


class StatsCollector:
    """Collects and computes live network statistics."""

    def __init__(self, window_seconds: float = 1.0):
        self.window_seconds = window_seconds
        self._packet_times: list[float] = []
        self._packet_sizes: list[int] = []
        self._lock = asyncio.Lock()
        self._stats = NetworkStats()
        self._protocol_counters: dict[str, int] = defaultdict(int)
        self._port_counters: dict[int, int] = defaultdict(int)

    def record_packet(self, pkt, protocol: str = "unknown", port: int = 0) -> None:
        """Record a packet for statistics."""
        now = time.time()
        size = len(pkt.raw_bytes) if hasattr(pkt, 'raw_bytes') else 0

        self._packet_times.append(now)
        self._packet_sizes.append(size)
        self._stats.packets_total += 1
        self._stats.bytes_total += size
        self._protocol_counters[protocol] += 1
        if port:
            self._port_counters[port] += 1

        self._cleanup_old(now)

    def _cleanup_old(self, now: float):
        cutoff = now - self.window_seconds
        while self._packet_times and self._packet_times[0] < cutoff:
            self._packet_times.pop(0)
            self._packet_sizes.pop(0)

    def get_stats(self, tcp_streams: int = 0, udp_flows: int = 0) -> NetworkStats:
        """Compute current statistics."""
        now = time.time()
        self._cleanup_old(now)

        window = self.window_seconds
        if len(self._packet_times) >= 2:
            actual_window = self._packet_times[-1] - self._packet_times[0]
            if actual_window > 0:
                window = actual_window

        self._stats.pps = len(self._packet_times) / window if window > 0 else 0
        self._stats.bps = sum(self._packet_sizes) / window if window > 0 else 0
        self._stats.active_flows = tcp_streams + udp_flows
        self._stats.tcp_streams = tcp_streams
        self._stats.udp_flows = udp_flows
        self._stats.by_protocol = dict(self._protocol_counters)
        self._stats.by_port = dict(self._port_counters)
        self._stats.timestamp = datetime.now()

        return self._stats

    def reset(self) -> None:
        self._packet_times.clear()
        self._packet_sizes.clear()
        self._protocol_counters.clear()
        self._port_counters.clear()
        self._stats = NetworkStats()


class LiveStatsBroadcaster:
    """Broadcasts live stats via WebSocket."""

    def __init__(self, collector: StatsCollector, interval: float = 1.0):
        self.collector = collector
        self.interval = interval
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._subscribers: list[asyncio.Queue] = []

    async def start(self, tcp_streams_getter, udp_flows_getter):
        if self._running:
            return
        self._running = True
        self._tcp_getter = tcp_streams_getter
        self._udp_getter = udp_flows_getter
        self._task = asyncio.create_task(self._broadcast_loop())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue()
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    async def _broadcast_loop(self):
        while self._running:
            try:
                tcp = self._tcp_getter() if callable(self._tcp_getter) else 0
                udp = self._udp_getter() if callable(self._udp_getter) else 0
                stats = self.collector.get_stats(tcp, udp)

                for queue in self._subscribers:
                    try:
                        queue.put_nowait(stats)
                    except asyncio.QueueFull:
                        pass

                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Stats broadcast error: %s", e)
                await asyncio.sleep(self.interval)