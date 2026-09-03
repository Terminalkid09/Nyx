"""MITM-scoped packet capture feed.

The Network tab captures the whole LAN with a user-managed lifecycle. The
MITM page instead needs a packet-level view scoped to the devices under
interception: this feed is started and stopped AUTOMATICALLY by the MITM
start/stop endpoints and BPF-filters to the target IPs, so its bounded
buffer holds only the intercepted devices' traffic (plus DHCP handshake
frames, useful to debug the rogue-DHCP fallback path).

Failure policy: capture is a *view*, not the interception path. If Npcap is
missing, the interface cannot be opened or the sniffer errors, the feed
degrades to ``feed_status() = {"running": False, "error": ...}`` and the
MITM keeps working — the UI shows the reason instead of packets.

The feed reuses NetworkEngine (same dissectors/watchdog as the Network tab)
with small buffers: it is a convenience view, not a recording tool.
"""
import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

_feed_engine = None
_feed_task: Optional[asyncio.Task] = None
_feed_error: Optional[str] = None
_feed_targets: set[str] = set()
_feed_started_ts: Optional[float] = None
# Serialises start/stop (double Start clicks must not create two engines).
_feed_lock = asyncio.Lock()


def build_target_bpf(target_ips: set[str], include_dhcp: bool = True) -> str:
    """BPF that matches any packet where a target is an endpoint.

    ``host <ip>`` matches src OR dst at the IP layer (and the corresponding
    protocol addresses in ARP). The DHCP clause keeps broadcast DISCOVER /
    OFFER frames visible: their IP endpoints (0.0.0.0 / 255.255.255.255)
    match no ``host`` term, yet they are exactly what one watches during a
    rogue-DHCP takeover.

    Every IP is validated before being embedded: the BPF string is a capture
    filter, so garbage in ``target_ips`` must never reach it (defense in
    depth — the start endpoint validates too, this makes the builder safe
    regardless of the caller).
    """
    import ipaddress as _ipaddress

    parts: list[str] = []
    for ip in sorted(target_ips):
        if not ip:
            continue
        try:
            addr = _ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("MITM feed: dropping invalid target IP %r from BPF", ip)
            continue
        parts.append(f"host {addr}")
    if include_dhcp:
        parts.append("(port 67 or port 68)")
    return " or ".join(parts) if parts else "arp"


async def start_feed(target_ips: set[str], gateway_ip: Optional[str] = None) -> None:
    """Start the target-scoped capture (non-fatal on failure).

    Called from POST /api/mitm/start. Any error is recorded in the feed
    status and surfaced by the UI — never propagated to the MITM start.
    """
    global _feed_engine, _feed_task, _feed_error, _feed_targets, _feed_started_ts

    async with _feed_lock:
        if _feed_engine is not None:
            return  # already running (double-start guard)
        _feed_error = None
        # Gateway only stored for the status view: it is already covered by
        # the ``host <target>`` terms (target<->gateway traffic has the
        # target as an endpoint). Putting it in the BPF too would pull the
        # router's own unrelated traffic into the buffer.
        targets = {ip for ip in target_ips if ip and ip != gateway_ip}
        if not targets:
            _feed_error = "no target IPs to scope the capture"
            return
        _feed_targets = targets
        try:
            from modules.network.engine import NetworkEngine

            engine = NetworkEngine(
                interface="auto",
                bpf_filter=build_target_bpf(targets),
                # Small on purpose: the MITM feed is a live view, not an
                # archive (the .pcap record lives in the Network tab).
                max_packets=400,
                max_frames=200,
            )
            await engine.start()
            _feed_task = asyncio.create_task(engine.run_async())
            _feed_engine = engine
            _feed_started_ts = time.time()
            logger.info(
                "MITM packet feed started on %s (BPF: %s)",
                engine.interface, engine.bpf_filter,
            )
        except Exception as e:
            _feed_engine = None
            _feed_task = None
            _feed_error = str(e) or type(e).__name__
            logger.warning("MITM packet feed failed to start (non-fatal): %s", e)


async def stop_feed() -> None:
    """Stop the feed and drop its buffer (called from POST /api/mitm/stop)."""
    global _feed_engine, _feed_task, _feed_targets, _feed_started_ts

    async with _feed_lock:
        engine, task = _feed_engine, _feed_task
        _feed_engine = None
        _feed_task = None
        _feed_targets = set()
        _feed_started_ts = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        if engine is not None:
            try:
                await engine.stop()
            except Exception as e:
                logger.debug("MITM packet feed stop error: %s", e)
        logger.info("MITM packet feed stopped")


def feed_status() -> dict:
    """Compact status for the MITM /status payload (absent-safe fields)."""
    engine = _feed_engine
    return {
        "running": engine is not None,
        "interface": engine.interface if engine is not None else None,
        "targets": sorted(_feed_targets),
        "packets_buffered": len(engine.recent_packets) if engine is not None else 0,
        "error": _feed_error,
        "started_ts": _feed_started_ts,
    }


def recent_packets(limit: int = 120) -> list[dict]:
    """Most recent packet summaries (oldest-first, bounded)."""
    engine = _feed_engine
    if engine is None:
        return []
    items = list(engine.recent_packets)
    return items[-max(1, min(int(limit), 400)):]
