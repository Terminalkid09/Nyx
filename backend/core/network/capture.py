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
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)


def _iface_name_for_ip(ip: str) -> str:
    """Map an interface IP address to its OS interface name (psutil)."""
    try:
        import psutil
        for name, addr_list in psutil.net_if_addrs().items():
            for a in addr_list:
                if a.family == socket.AF_INET and a.address == ip:
                    return name
    except Exception:
        pass
    return ""


def _scapy_friendly_name(device_or_ip: str) -> str:
    """Map an Npcap device name (GUID), network name or IP to the friendly
    interface name (e.g. 'Wi-Fi') via scapy's interface table.

    On Windows scapy's routing table and conf.iface speak in Npcap device
    names (\\Device\\NPF_{GUID}); the API, UI and psutil all use the friendly
    name — normalise to that so "auto" resolves to the same string the user
    can type back into capture/start.
    """
    try:
        from scapy.all import conf
        for key, iface in conf.ifaces.items():
            try:
                if device_or_ip in (
                    str(key or ""),
                    str(getattr(iface, "network_name", "") or ""),
                    str(getattr(iface, "ip", "") or ""),
                ):
                    name = str(getattr(iface, "name", "") or "")
                    if name and not name.startswith("\\Device\\"):
                        return name
            except Exception:
                continue
    except Exception:
        pass
    return ""


# Interface resolution is expensive on Windows (VPN adapters: scapy's
# conf.ifaces + routing resync + psutil polling can each take seconds) — and
# it must NEVER run on FastAPI's single asyncio event loop (it would freeze
# every HTTP request, e.g. /status and /capture/stop, behind the block).
# Callers on the loop use asyncio.to_thread(...); this cache additionally
# stops repeated cheap lookups (e.g. /interfaces polling) from re-enumerating
# the whole adapter table every call.
_RESOLVE_CACHE_TTL = 3.0  # seconds
_resolve_cache: Optional[tuple] = None  # (monotonic_ts, name)


def _resolve_active_interface_uncached() -> str:
    """The actual (expensive) resolution — see resolve_active_interface()."""
    # 1) scapy's routing table (refreshed — resync is cheap and keeps the
    #    table current after network changes).
    try:
        from scapy.all import conf
        try:
            conf.route.resync()
        except Exception:
            pass
        r = conf.route.route("0.0.0.0")
        if r and r[0]:
            val = str(r[0])
            name = _scapy_friendly_name(val) or _iface_name_for_ip(val)
            if name:
                return name
    except Exception:
        pass

    # 2) scapy's import-time default interface (GUID → friendly name).
    try:
        from scapy.all import conf
        if conf.iface:
            return _scapy_friendly_name(str(conf.iface)) or str(conf.iface)
    except Exception:
        pass

    # 3) psutil heuristic.
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, addr_list in psutil.net_if_addrs().items():
            st = stats.get(name)
            if st is None or not st.isup:
                continue
            if name.lower().startswith(("lo", "loopback")):
                continue
            if any(a.family == socket.AF_INET for a in addr_list):
                return name
    except Exception:
        pass
    return ""


def resolve_active_interface(cached: bool = True) -> str:
    """Best-effort name of the interface that currently owns the default route.

    Used for adaptive capture: ``interface: "auto"`` resolves to the live
    interface (e.g. "Wi-Fi"), and the engine's watchdog re-resolves it every
    few seconds so a Wi-Fi→Ethernet switch triggers a capture rebind.
    Resolution order: scapy's live routing table → scapy's import-time
    default → psutil heuristic (first up, non-loopback adapter with IPv4).
    Returns "" when nothing can be resolved.

    ``cached=True`` (default) reuses the last result within a short TTL —
    enough for UI polling. The watchdog passes ``cached=False`` so adaptive
    capture still notices interface switches; it runs inside
    ``asyncio.to_thread`` there, so the event loop never blocks on the
    (potentially seconds-long) scapy/psutil enumeration.
    """
    global _resolve_cache
    if cached and _resolve_cache is not None:
        ts, name = _resolve_cache
        if time.monotonic() - ts < _RESOLVE_CACHE_TTL:
            return name
    name = _resolve_active_interface_uncached()
    if name:
        _resolve_cache = (time.monotonic(), name)
    return name


def list_capture_interfaces() -> List[dict]:
    """Enumerate capturable interfaces for the UI dropdown.

    Each entry: {name, is_up, is_loopback, ipv4, is_default} where
    is_default marks the interface owning the default route right now
    (the one ``interface: "auto"`` would pick).
    """
    default = resolve_active_interface()
    out: List[dict] = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, addr_list in psutil.net_if_addrs().items():
            ipv4 = [a.address for a in addr_list if a.family == socket.AF_INET]
            st = stats.get(name)
            is_loopback = name.lower().startswith(("lo", "loopback"))
            out.append({
                "name": name,
                "is_up": bool(st.isup) if st else False,
                "is_loopback": is_loopback,
                "ipv4": ipv4,
                "is_default": name == default,
            })
    except Exception as e:
        logger.debug("Interface enumeration failed: %s", e)
    # The resolved default is offered even if psutil missed it (VPN adapters).
    if default and not any(i["name"] == default for i in out):
        out.append({
            "name": default, "is_up": True, "is_loopback": False,
            "ipv4": [], "is_default": True,
        })
    return out


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
        """Yield queued RawPackets until stopped and drained.

        Sync-only helper (e.g. tests / CLI use). Async consumers must use
        ``next_packet_async()`` instead — this generator calls the blocking
        ``queue.get(timeout=0.2)``, which would freeze the event loop.
        """
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

    async def next_packet_async(self) -> Optional[RawPacket]:
        """Return the next queued packet without ever blocking the event loop.

        The sniffer pushes RawPackets from its own thread; draining must use
        ``get_nowait()`` + a short sleep instead of the blocking
        ``queue.get(timeout=...)``, which would stall MITM, the scanners and
        every WebSocket handler for up to the timeout on each empty poll.
        Returns None once capture is stopped AND the queue is drained.
        """
        while True:
            try:
                return self._packet_queue.get_nowait()
            except queue.Empty:
                if not self._running and self._packet_queue.empty():
                    return None
                await asyncio.sleep(0.01)

    async def run_async(self) -> None:
        """Run the capture loop asynchronously, calling callbacks."""
        while True:
            pkt = await self.next_packet_async()
            if pkt is None:
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
