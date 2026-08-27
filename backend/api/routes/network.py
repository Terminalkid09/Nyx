"""REST API routes for the network layer.

Endpoints:
  GET  /api/network/status              — engine state + live stats
  POST /api/network/capture/start       — start capture on an interface
  POST /api/network/capture/stop        — stop and report packet count
  GET  /api/network/packets             — recent packet summaries
  GET  /api/network/frames              — recent protocol frames
  GET  /api/network/streams             — TCP streams + UDP flows
  GET  /api/network/streams/{id}/frames — frames of one stream
  GET  /api/network/export              — download recent packets as .pcap
  WS   /api/network/ws/live             — live stats + frames

HTTP/TLS streams carry a `link` hint pointing at the Proxy tab: the packet
view intentionally does NOT parse HTTP/TLS — mitmproxy (LoggerAddon) already
captures those flows, so the UI links to them instead.
"""
import asyncio
import logging
import os
import tempfile
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.background import BackgroundTask

from core.network.pcap import PCAPWriter
from core.network.protocols.base import FiveTuple
from core.network.stats import StatsCollector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/network", tags=["network"])

_network_engine = None
_capture_task: Optional[asyncio.Task] = None
_event_bus = None
_stats_collector = StatsCollector()

_TLS_PORTS = (443, 8443, 9443, 993, 995, 5223, 8883)
_HTTP_PORTS = (80, 8080, 8000, 8888)


class _LiveFeed:
    """Pushes periodic stats + live frames to per-connection queues."""

    def __init__(self, collector: StatsCollector, interval: float = 1.0):
        self._collector = collector
        self._interval = interval
        self._queues: list[asyncio.Queue] = []
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self._queues:
            self._queues.remove(q)

    def _put(self, q: asyncio.Queue, msg: dict):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            # Consumer is behind — drop the stale entry, keep the newest.
            try:
                q.get_nowait()
                q.put_nowait(msg)
            except asyncio.QueueEmpty:
                pass

    def push_frame(self, frame_dict: dict):
        for q in list(self._queues):
            self._put(q, {"type": "frame", "data": frame_dict})

    async def _loop(self):
        while self._running:
            try:
                stats = self._current_stats()
                for q in list(self._queues):
                    self._put(q, {"type": "stats", "data": stats.to_dict()})
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Live feed error: %s", e)
                await asyncio.sleep(self._interval)

    def _current_stats(self):
        tcp = udp = 0
        if _network_engine is not None:
            tcp = len(_network_engine.tcp_reassembler.get_all_streams())
            udp = len(_network_engine.udp_tracker.get_all_flows())
        return self._collector.get_stats(tcp, udp)


_live_feed = _LiveFeed(_stats_collector)


def init_network(event_bus=None, engine=None):
    """Wire the capture engine + event bus (called from main.py)."""
    global _event_bus, _network_engine
    _event_bus = event_bus
    if engine is not None:
        _network_engine = engine
        engine.on_frame(_live_feed.push_frame)
    _live_feed.start()


async def shutdown_network():
    """Stop the live feed and the engine (called from main.py lifespan)."""
    global _network_engine, _capture_task
    _live_feed.stop()
    engine = _network_engine
    _network_engine = None
    if engine is not None:
        try:
            await engine.stop()
        except Exception as e:
            logger.warning("Network engine stop during shutdown failed: %s", e)
    if _capture_task is not None:
        _capture_task.cancel()
        try:
            await _capture_task
        except asyncio.CancelledError:
            pass
        _capture_task = None


# ── models ──────────────────────────────────────────────────────────────────


class NetworkStatus(BaseModel):
    running: bool
    interface: str
    bpf_filter: str
    pcap_path: Optional[str]
    stats: dict
    tcp_streams: int
    udp_flows: int
    packets_buffered: int
    frames_buffered: int


class CaptureStartRequest(BaseModel):
    interface: str
    bpf_filter: str = "tcp or udp"
    snaplen: int = 65535
    promisc: bool = True
    pcap_path: Optional[str] = None


class CaptureStopResponse(BaseModel):
    packets_captured: int
    pcap_path: Optional[str]


class StreamSummary(BaseModel):
    stream_id: str
    five_tuple: dict
    transport: str  # "tcp" | "udp"
    frame_count: int
    start_time: datetime
    last_seen: datetime
    bytes_total: int
    sni: Optional[str] = None
    link: Optional[dict] = None  # {"type": "proxy", "protocol": "http"|"tls"}


class FrameSummary(BaseModel):
    frame_type: str
    timestamp: datetime
    data: dict


# ── helpers ─────────────────────────────────────────────────────────────────


def _stream_id(ft: FiveTuple) -> str:
    return f"{ft.src_ip}-{ft.dst_ip}-{ft.src_port}-{ft.dst_port}-{ft.protocol}"


def _five_tuple_to_dict(ft: FiveTuple) -> dict:
    return {
        "src_ip": ft.src_ip,
        "dst_ip": ft.dst_ip,
        "src_port": ft.src_port,
        "dst_port": ft.dst_port,
        "protocol": ft.protocol,
    }


def _proxy_link(ft: FiveTuple) -> Optional[dict]:
    """Hint for the UI: HTTP/TLS flows live in the mitmproxy Proxy tab."""
    if ft.protocol != 6:
        return None
    if ft.dst_port in _HTTP_PORTS:
        return {"type": "proxy", "protocol": "http"}
    if ft.dst_port in _TLS_PORTS:
        return {"type": "proxy", "protocol": "tls"}
    return None


# ── endpoints ───────────────────────────────────────────────────────────────


@router.get("/status", response_model=NetworkStatus)
async def get_status():
    if not _network_engine:
        return NetworkStatus(
            running=False,
            interface="",
            bpf_filter="",
            pcap_path=None,
            stats=_stats_collector.get_stats(0, 0).to_dict(),
            tcp_streams=0,
            udp_flows=0,
            packets_buffered=0,
            frames_buffered=0,
        )

    tcp_count = len(_network_engine.tcp_reassembler.get_all_streams())
    udp_count = len(_network_engine.udp_tracker.get_all_flows())
    stats = _stats_collector.get_stats(tcp_count, udp_count)

    return NetworkStatus(
        running=True,
        interface=_network_engine.interface,
        bpf_filter=_network_engine.bpf_filter,
        pcap_path=_network_engine.pcap_path,
        stats=stats.to_dict(),
        tcp_streams=tcp_count,
        udp_flows=udp_count,
        packets_buffered=len(_network_engine.recent_packets),
        frames_buffered=len(_network_engine.recent_frames),
    )


@router.post("/capture/start", response_model=dict)
async def start_capture(request: CaptureStartRequest):
    global _network_engine, _capture_task

    if _network_engine:
        raise HTTPException(status_code=409, detail="Capture already running")

    from modules.network.engine import NetworkEngine

    engine = NetworkEngine(
        interface=request.interface,
        bpf_filter=request.bpf_filter,
        snaplen=request.snaplen,
        promisc=request.promisc,
        event_bus=_event_bus,
    )

    if request.pcap_path:
        writer = PCAPWriter(request.pcap_path)
        writer.open()
        engine.set_pcap_output(writer)

    _stats_collector.reset()
    _network_engine = engine
    engine.on_frame(_live_feed.push_frame)

    try:
        await engine.start()
    except Exception as e:
        _network_engine = None
        raise HTTPException(status_code=500, detail=f"Capture start failed: {e}")

    _capture_task = asyncio.create_task(engine.run_async())

    return {
        "status": "started",
        "interface": request.interface,
        "pcap_path": request.pcap_path,
    }


@router.post("/capture/stop", response_model=CaptureStopResponse)
async def stop_capture():
    global _network_engine, _capture_task

    if not _network_engine:
        return CaptureStopResponse(packets_captured=0, pcap_path=None)

    pcap_path = _network_engine.pcap_path
    packet_count = _stats_collector._stats.packets_total

    await _network_engine.stop()
    _network_engine = None

    if _capture_task:
        _capture_task.cancel()
        try:
            await _capture_task
        except asyncio.CancelledError:
            pass
        _capture_task = None

    return CaptureStopResponse(
        packets_captured=packet_count,
        pcap_path=pcap_path,
    )


@router.get("/packets")
async def get_packets(limit: int = 200):
    if not _network_engine:
        return []
    return _network_engine.get_packet_list(limit=limit)


@router.get("/frames")
async def get_frames(limit: int = 200):
    if not _network_engine:
        return []
    return _network_engine.get_frame_list(limit=limit)


@router.get("/streams", response_model=list[StreamSummary])
async def get_streams():
    if not _network_engine:
        return []

    summaries = []
    for stream in _network_engine.tcp_reassembler.get_all_streams():
        ft = stream.five_tuple
        summaries.append(StreamSummary(
            stream_id=_stream_id(ft),
            five_tuple=_five_tuple_to_dict(ft),
            transport="tcp",
            frame_count=len(stream.frames),
            start_time=stream.start_time or datetime.now(),
            last_seen=stream.last_seen or datetime.now(),
            bytes_total=sum(len(f.payload) for f in stream.frames),
            sni=stream.metadata.get("sni"),
            link=_proxy_link(ft),
        ))

    for flow in _network_engine.udp_tracker.get_all_flows():
        ft = flow.five_tuple
        summaries.append(StreamSummary(
            stream_id=_stream_id(ft),
            five_tuple=_five_tuple_to_dict(ft),
            transport="udp",
            frame_count=len(flow.packets),
            start_time=flow.start_time or datetime.now(),
            last_seen=flow.last_seen or datetime.now(),
            bytes_total=sum(p.length for p in flow.packets),
            link=_proxy_link(ft),
        ))

    return summaries


@router.get("/streams/{stream_id}/frames", response_model=list[FrameSummary])
async def get_stream_frames(stream_id: str, limit: int = 100):
    if not _network_engine:
        return []

    parts = stream_id.split("-")
    if len(parts) != 5:
        return []

    five_tuple = FiveTuple(
        src_ip=parts[0],
        dst_ip=parts[1],
        src_port=int(parts[2]),
        dst_port=int(parts[3]),
        protocol=int(parts[4])
    )

    stream = _network_engine.tcp_reassembler.get_stream(five_tuple)
    if not stream:
        flow = _network_engine.udp_tracker.get_flow(five_tuple)
        if not flow:
            return []
        frames = []
        for pkt in flow.packets[-limit:]:
            frames.append(FrameSummary(
                frame_type="udp_packet",
                timestamp=pkt.timestamp,
                data={"length": pkt.length, "payload": pkt.payload[:100].hex()}
            ))
        return frames

    frames = []
    for f in stream.frames[-limit:]:
        frames.append(FrameSummary(
            frame_type="tcp_frame",
            timestamp=f.timestamp,
            data={
                "seq": f.seq_start,
                "end_seq": f.seq_end,
                "flags": f.flags,
                "payload_length": len(f.payload),
                "is_client": f.is_client,
                "payload": f.payload[:100].hex(),
            }
        ))
    return frames


@router.get("/export")
async def export_pcap():
    """Download the buffered packets as a .pcap file."""
    if not _network_engine or not _network_engine.recent_raw_packets:
        raise HTTPException(status_code=404, detail="Nothing to export — start a capture first")

    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="nyx-network-")
    os.close(fd)

    writer = PCAPWriter(path)
    writer.open()
    for pkt in _network_engine.recent_raw_packets:
        writer.write_packet(pkt)
    writer.close()

    return FileResponse(
        path,
        filename="nyx-network-capture.pcap",
        media_type="application/vnd.tcpdump.pcap",
        background=BackgroundTask(os.unlink, path),
    )


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    from core.api_auth import validate_ws_origin

    if not validate_ws_origin(websocket):
        logger.warning("Rejected network WebSocket from foreign origin")
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Immediate snapshot so the UI renders before the first tick.
    await websocket.send_json({
        "type": "stats",
        "data": _live_feed._current_stats().to_dict(),
    })

    queue = _live_feed.subscribe()
    try:
        while True:
            msg = await queue.get()
            await websocket.send_json(msg)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("Network WebSocket error: %s", e)
    finally:
        _live_feed.unsubscribe(queue)
