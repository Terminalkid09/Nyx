"""Network module - high-level orchestration."""

from modules.network.engine import NetworkEngine
from modules.network.mitm_integration import (
    extract_sni_from_payload,
    extract_sni_from_stream,
    feed_mitmproxy_from_stream,
)
from modules.network.tasks import CaptureCleanupTask, StatsAggregationTask

__all__ = [
    "NetworkEngine",
    "extract_sni_from_payload",
    "extract_sni_from_stream",
    "feed_mitmproxy_from_stream",
    "CaptureCleanupTask",
    "StatsAggregationTask",
]
