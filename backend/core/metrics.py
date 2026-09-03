"""Zero-dependency Prometheus-compatible metrics collector.

Exposes a ``/metrics`` endpoint that Prometheus / Grafana / VictoriaMetrics can
scrape. All counters are process-local (no push gateway, no external dep).
"""
import threading
import time


class MetricsRegistry:
    """Thread-safe registry of counters and gauges."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._start_time = time.time()

    # ── Counters (monotonically increasing) ──────────────────────────────

    def inc(self, name: str, delta: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + delta

    def counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    # ── Gauges (up/down values) ───────────────────────────────────────────

    def set(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def get(self, name: str) -> float:
        with self._lock:
            return self._gauges.get(name, 0.0)

    # ── Prometheus text format ────────────────────────────────────────────

    def render(self) -> str:
        """Return the full Prometheus exposition text."""
        with self._lock:
            lines: list[str] = []

            # HELP/TYPE for counters
            for name, value in sorted(self._counters.items()):
                safe = name.replace("-", "_").replace(".", "_").replace(" ", "_")
                lines.append(f"# HELP nyx_{safe} Nyx {name}")
                lines.append(f"# TYPE nyx_{safe} counter")
                lines.append(f"nyx_{safe} {value}")

            # HELP/TYPE for gauges
            for name, value in sorted(self._gauges.items()):
                safe = name.replace("-", "_").replace(".", "_").replace(" ", "_")
                lines.append(f"# HELP nyx_{safe} Nyx {name}")
                lines.append(f"# TYPE nyx_{safe} gauge")
                lines.append(f"nyx_{safe} {value}")

            # Process uptime
            uptime = time.time() - self._start_time
            lines.append("# HELP nyx_process_uptime_seconds Nyx backend process uptime")
            lines.append("# TYPE nyx_process_uptime_seconds gauge")
            lines.append(f"nyx_process_uptime_seconds {uptime:.2f}")

            lines.append("")  # trailing newline
            return "\n".join(lines)


# Global singleton — imported once, shared across modules.
registry = MetricsRegistry()