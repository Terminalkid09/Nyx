import asyncio
import logging
from datetime import datetime, timezone
from core.events.bus import EventBus

logger = logging.getLogger(__name__)

class LiveAuditService:
    """
    Continuous live audit mode for proxy traffic.
    Extends AutoScanEngine with interactive controls and detailed audit logging.
    """

    def __init__(self, event_bus: EventBus, auto_scan_engine=None):
        self.event_bus = event_bus
        self.auto_scan_engine = auto_scan_engine
        self._running = False
        self._audit_log: list[dict] = []
        self._max_log_entries = 1000
        # Engine flags as they were before Live Audit took control, restored on
        # stop so stopping the audit does not silently disable a scan the user
        # enabled from the Automation page.
        self._prev_auto_active: bool | None = None
        self._prev_param_discovery: bool | None = None
        self._prev_enforce_scope: bool | None = None
        self._config = {
            "passive_scan": True,
            "active_scan": True,
            "param_discovery": False,
            "max_concurrent_audits": 5,
            "scope_only": True,
            "throttle_ms": 200,
            "log_all": False,
        }
        self._stats = {
            "requests_analyzed": 0,
            "responses_analyzed": 0,
            "passive_findings": 0,
            "active_scans_queued": 0,
            "active_scans_completed": 0,
            "active_findings": 0,
            "errors": 0,
            "started_at": None,
        }

    async def start(self):
        if self._running:
            return
        self._running = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()

        self.event_bus.subscribe("request.captured", self._on_request)
        self.event_bus.subscribe("response.received", self._on_response)
        # Findings are counted from the canonical "finding.created" events —
        # the PassiveScanner runs exactly once via its own bus subscription,
        # so re-running checks here would only duplicate work.
        self.event_bus.subscribe("finding.created", self._on_finding_created)
        self.event_bus.subscribe("automation.scan_started", self._on_scan_started)
        self.event_bus.subscribe("automation.scan_completed", self._on_scan_completed)

        if self.auto_scan_engine:
            self.auto_scan_engine._running = True
            self._take_engine_control()

        logger.info("Live Audit started")
        await self.event_bus.publish({
            "type": "live_audit.status_changed",
            "status": "running",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def stop(self):
        if not self._running:
            return
        self._running = False
        self.event_bus.unsubscribe("request.captured", self._on_request)
        self.event_bus.unsubscribe("response.received", self._on_response)
        self.event_bus.unsubscribe("finding.created", self._on_finding_created)
        self.event_bus.unsubscribe("automation.scan_started", self._on_scan_started)
        self.event_bus.unsubscribe("automation.scan_completed", self._on_scan_completed)
        self._restore_engine_flags()
        logger.info("Live Audit stopped: %s findings from %s requests",
                    self._stats["passive_findings"] + self._stats["active_findings"],
                    self._stats["requests_analyzed"])
        await self.event_bus.publish({
            "type": "live_audit.status_changed",
            "status": "stopped",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def _on_request(self, event: dict):
        if not self._running or not self._config["passive_scan"]:
            return
        self._stats["requests_analyzed"] += 1

        if self._config["log_all"]:
            self._log("request_analyzed", {
                "url": event.get("url", ""),
                "method": event.get("method", ""),
            })

    async def _on_response(self, event: dict):
        if not self._running or not self._config["passive_scan"]:
            return
        self._stats["responses_analyzed"] += 1

        if self._config["log_all"]:
            self._log("response_analyzed", {
                "url": event.get("url", ""),
                "status": event.get("status", ""),
            })

    async def _on_finding_created(self, event: dict):
        if not self._running:
            return
        if event.get("source") == "active":
            self._stats["active_findings"] += 1
        else:
            self._stats["passive_findings"] += 1

    def _log(self, event_type: str, data: dict):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "data": data,
        }
        self._audit_log.append(entry)
        if len(self._audit_log) > self._max_log_entries:
            self._audit_log.pop(0)

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "config": self._config,
            "stats": self._stats,
            "audit_log_count": len(self._audit_log),
            "recent_log": self._audit_log[-20:] if self._audit_log else [],
        }

    def _take_engine_control(self) -> None:
        """Apply the toggles to the auto-scan engine (they used to be inert)."""
        engine = self.auto_scan_engine
        if not engine:
            return
        if self._prev_auto_active is None:
            self._prev_auto_active = getattr(engine, "auto_active_scan", False)
        if self._prev_param_discovery is None:
            self._prev_param_discovery = getattr(engine, "auto_param_discovery", False)
        if self._prev_enforce_scope is None:
            self._prev_enforce_scope = getattr(engine, "enforce_scope", True)
        engine.auto_active_scan = bool(self._config["active_scan"])
        engine.auto_param_discovery = bool(self._config["param_discovery"])
        engine.enforce_scope = bool(self._config["scope_only"])

    def _restore_engine_flags(self) -> None:
        engine = self.auto_scan_engine
        if not engine:
            return
        if self._prev_auto_active is not None:
            engine.auto_active_scan = self._prev_auto_active
        if self._prev_param_discovery is not None:
            engine.auto_param_discovery = self._prev_param_discovery
        if self._prev_enforce_scope is not None:
            engine.enforce_scope = self._prev_enforce_scope
        self._prev_auto_active = None
        self._prev_param_discovery = None
        self._prev_enforce_scope = None

    async def _on_scan_started(self, event: dict) -> None:
        if self._running:
            self._stats["active_scans_queued"] += 1

    async def _on_scan_completed(self, event: dict) -> None:
        if self._running:
            self._stats["active_scans_completed"] += 1

    def update_config(self, config: dict) -> dict:
        for key, value in config.items():
            if key in self._config:
                self._config[key] = value
        if self._running:
            self._take_engine_control()
        return self._config

    def get_config(self) -> dict:
        return dict(self._config)

    def clear_stats(self):
        self._stats = {
            "requests_analyzed": 0,
            "responses_analyzed": 0,
            "passive_findings": 0,
            "active_scans_queued": 0,
            "active_scans_completed": 0,
            "active_findings": 0,
            "errors": 0,
            "started_at": self._stats.get("started_at"),
        }

    def clear_log(self):
        self._audit_log.clear()
