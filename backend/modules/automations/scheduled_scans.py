import asyncio
import json
import uuid
import logging
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from core.events.bus import EventBus

logger = logging.getLogger(__name__)

class ScheduledScanService:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._configs_path = Path(__file__).parent.parent.parent / "data" / "scheduled_scans.json"
        self._schedules = []
        self._task = None
        self._running = False
        self._load()

    def _load(self):
        if self._configs_path.exists():
            try:
                self._schedules = json.loads(self._configs_path.read_text())
            except Exception:
                self._schedules = []
        else:
            self._schedules = []

    def _save(self):
        self._configs_path.parent.mkdir(parents=True, exist_ok=True)
        self._configs_path.write_text(json.dumps(self._schedules, indent=2))

    def get_schedules(self) -> list[dict]:
        return self._schedules

    def add_schedule(self, schedule: dict) -> dict:
        schedule["id"] = str(uuid.uuid4())
        schedule["enabled"] = schedule.get("enabled", True)
        schedule["last_run"] = None
        schedule["next_run"] = None
        self._schedules.append(schedule)
        self._save()
        self._calculate_next_run(schedule)
        return schedule

    def update_schedule(self, schedule_id: str, data: dict) -> dict | None:
        for s in self._schedules:
            if s["id"] == schedule_id:
                s.update(data)
                self._save()
                return s
        return None

    def delete_schedule(self, schedule_id: str) -> bool:
        self._schedules = [s for s in self._schedules if s.get("id") != schedule_id]
        self._save()
        return True

    def _calculate_next_run(self, schedule: dict) -> str | None:
        """Calculate next run time based on cron-like schedule.
        Supports: "*/N * * * *" (every N minutes), "0 * * * *" (hourly), etc.
        """
        cron = schedule.get("cron", "")
        match = re.match(r"\*/(\d+) \* \* \* \*", cron)
        if match:
            interval = int(match.group(1))
            now = datetime.now(timezone.utc)
            next_time = now + timedelta(minutes=interval)
            schedule["next_run"] = next_time.isoformat()
            return schedule["next_run"]
        
        if cron == "0 * * * *":
            now = datetime.now(timezone.utc)
            next_time = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
            schedule["next_run"] = next_time.isoformat()
            return schedule["next_run"]
        
        if cron == "0 0 * * *":
            now = datetime.now(timezone.utc)
            next_time = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            schedule["next_run"] = next_time.isoformat()
            return schedule["next_run"]
        
        schedule["next_run"] = None
        return None

    def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._schedule_loop())
        logger.info("Scheduled scan service started")

    async def _schedule_loop(self):
        while self._running:
            now = datetime.now(timezone.utc)
            for s in self._schedules:
                if not s.get("enabled"):
                    continue
                next_run = s.get("next_run")
                if next_run:
                    try:
                        next_time = datetime.fromisoformat(next_run)
                        if now >= next_time:
                            await self._execute_scan(s)
                            s["last_run"] = now.isoformat()
                            self._calculate_next_run(s)
                            self._save()
                    except Exception as e:
                        logger.error("Scheduled scan %s failed: %s", s.get("id"), e)
            await asyncio.sleep(30)

    async def _execute_scan(self, schedule: dict):
        logger.info("Executing scheduled scan: %s", schedule.get("name", "unnamed"))
        await self.event_bus.publish({
            "type": "scheduled_scan.triggered",
            "schedule_id": schedule["id"],
            "name": schedule.get("name"),
            "target_url": schedule.get("target_url"),
            "config": schedule.get("config", {}),
        })

    def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
