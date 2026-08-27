"""Background tasks for network module."""
import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from core.network.pcap import PCAPWriter
from core.network.stats import StatsCollector

logger = logging.getLogger(__name__)


class CaptureCleanupTask:
    """Periodic cleanup of old capture files."""

    def __init__(
        self,
        capture_dir: str = "captures",
        max_age_days: int = 7,
        max_size_mb: int = 1024,
        interval_hours: int = 6
    ):
        self.capture_dir = Path(capture_dir)
        self.max_age = timedelta(days=max_age_days)
        self.max_size = max_size_mb * 1024 * 1024
        self.interval = interval_hours * 3600
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._cleanup_loop())
        logger.info("Capture cleanup task started")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _cleanup_loop(self):
        while self._running:
            try:
                await self._cleanup()
            except Exception as e:
                logger.error("Cleanup error: %s", e)
            await asyncio.sleep(self.interval)

    async def _cleanup(self):
        if not self.capture_dir.exists():
            return

        now = datetime.now()
        total_size = 0
        files = []

        for f in self.capture_dir.glob("*.pcap*"):
            try:
                stat = f.stat()
                age = now - datetime.fromtimestamp(stat.st_mtime)
                if age > self.max_age:
                    f.unlink()
                    logger.info("Deleted old capture: %s", f)
                else:
                    files.append((f, stat.st_size, stat.st_mtime))
                    total_size += stat.st_size
            except Exception as e:
                logger.debug("Error checking file %s: %s", f, e)

        if total_size > self.max_size:
            files.sort(key=lambda x: x[2])
            for f, size, _ in files:
                if total_size <= self.max_size:
                    break
                try:
                    f.unlink()
                    total_size -= size
                    logger.info("Deleted capture for size limit: %s", f)
                except Exception as e:
                    logger.debug("Error deleting file %s: %s", f, e)


class StatsAggregationTask:
    """Periodic aggregation and persistence of network statistics."""

    def __init__(
        self,
        stats_collector: StatsCollector,
        output_dir: str = "stats",
        interval_seconds: int = 60
    ):
        self.stats_collector = stats_collector
        self.output_dir = Path(output_dir)
        self.interval = interval_seconds
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        if self._running:
            return
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._running = True
        self._task = asyncio.create_task(self._aggregation_loop())
        logger.info("Stats aggregation task started")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _aggregation_loop(self):
        while self._running:
            try:
                await self._write_stats()
            except Exception as e:
                logger.error("Stats aggregation error: %s", e)
            await asyncio.sleep(self.interval)

    async def _write_stats(self):
        stats = self.stats_collector.get_stats()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = self.output_dir / f"stats_{timestamp}.json"

        import json
        data = {
            "timestamp": stats.timestamp.isoformat(),
            "pps": stats.pps,
            "bps": stats.bps,
            "active_flows": stats.active_flows,
            "tcp_streams": stats.tcp_streams,
            "udp_flows": stats.udp_flows,
            "bytes_total": stats.bytes_total,
            "packets_total": stats.packets_total,
            "errors": stats.errors,
            "by_protocol": stats.by_protocol,
            "by_port": stats.by_port,
        }

        try:
            filepath.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.debug("Failed to write stats: %s", e)


class PCAPRotationTask:
    """Automatic PCAP file rotation based on size/time."""

    def __init__(
        self,
        base_path: str,
        max_size_mb: int = 100,
        max_duration_seconds: int = 3600
    ):
        self.base_path = Path(base_path)
        self.max_size = max_size_mb * 1024 * 1024
        self.max_duration = max_duration_seconds
        self._current_writer: Optional[PCAPWriter] = None
        self._start_time: Optional[datetime] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        if self._running:
            return
        self.base_path.parent.mkdir(parents=True, exist_ok=True)
        self._running = True
        self._rotate()
        logger.info("PCAP rotation task started")

    async def stop(self):
        self._running = False
        if self._current_writer:
            self._current_writer.close()
            self._current_writer = None

    def _rotate(self):
        if self._current_writer:
            self._current_writer.close()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = self.base_path.parent / f"{self.base_path.stem}_{timestamp}.pcap"
        self._current_writer = PCAPWriter(str(filepath))
        self._current_writer.open()
        self._start_time = datetime.now()
        logger.info("Rotated PCAP to: %s", filepath)

    def write_packet(self, pkt):
        if not self._running or not self._current_writer:
            return

        self._current_writer.write_packet(pkt)

        if self._current_writer._packet_count > 0:
            try:
                current_size = self._current_writer.path.stat().st_size
                if current_size >= self.max_size:
                    self._rotate()
                    return

                if self._start_time:
                    elapsed = (datetime.now() - self._start_time).total_seconds()
                    if elapsed >= self.max_duration:
                        self._rotate()
                        return
            except Exception:
                pass