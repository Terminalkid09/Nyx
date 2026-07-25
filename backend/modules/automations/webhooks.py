import json
import logging
import uuid
import httpx
from pathlib import Path
from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import Finding
from sqlalchemy import select

logger = logging.getLogger(__name__)

class WebhookService:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._configs = []
        self._load_configs()

    def _load_configs(self):
        config_path = Path(__file__).parent.parent.parent / "data" / "webhooks.json"
        if config_path.exists():
            try:
                self._configs = json.loads(config_path.read_text())
            except Exception:
                self._configs = []
        else:
            self._configs = []

    def _save_configs(self):
        config_path = Path(__file__).parent.parent.parent / "data" / "webhooks.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(self._configs, indent=2))

    def get_configs(self) -> list[dict]:
        return self._configs

    def add_config(self, config: dict) -> dict:
        config["id"] = str(uuid.uuid4())
        config["enabled"] = config.get("enabled", True)
        self._configs.append(config)
        self._save_configs()
        return config

    def update_config(self, config_id: str, config: dict) -> dict | None:
        for i, c in enumerate(self._configs):
            if c.get("id") == config_id:
                self._configs[i].update(config)
                self._save_configs()
                return self._configs[i]
        return None

    def delete_config(self, config_id: str) -> bool:
        self._configs = [c for c in self._configs if c.get("id") != config_id]
        self._save_configs()
        return True

    async def send_alert(self, title: str, message: str, severity: str = "info", fields: list[dict] = None):
        for config in self._configs:
            if not config.get("enabled"):
                continue
            try:
                if config.get("type") == "slack":
                    await self._send_slack(config, title, message, severity, fields)
                elif config.get("type") == "discord":
                    await self._send_discord(config, title, message, severity, fields)
            except Exception as e:
                logger.error("Webhook %s failed: %s", config.get("name"), e)

    async def _send_slack(self, config: dict, title: str, message: str, severity: str, fields: list[dict] = None):
        color_map = {"critical": "#ff0000", "high": "#ff6600", "medium": "#ffcc00", "low": "#cccccc", "info": "#6699ff"}
        attachments = [{
            "color": color_map.get(severity, "#cccccc"),
            "title": title,
            "text": message,
            "fields": fields or [],
            "footer": "Nyx Security Scanner",
        }]
        payload = {"attachments": attachments}
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(config["url"], json=payload)

    async def _send_discord(self, config: dict, title: str, message: str, severity: str, fields: list[dict] = None):
        color_map = {"critical": 0xff0000, "high": 0xff6600, "medium": 0xffcc00, "low": 0xcccccc, "info": 0x6699ff}
        embed = {
            "title": title,
            "description": message,
            "color": color_map.get(severity, 0xcccccc),
            "fields": fields or [],
            "footer": {"text": "Nyx Security Scanner"},
        }
        payload = {"embeds": [embed]}
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(config["url"], json=payload)

    async def subscribe_to_events(self):
        """Subscribe to finding.created events to auto-send webhooks."""
        self.event_bus.subscribe("finding.created", self._on_finding_created)

    def stop(self):
        self.event_bus.unsubscribe("finding.created", self._on_finding_created)

    async def _on_finding_created(self, event: dict):
        severity = event.get("severity", "info")
        await self.send_alert(
            title=event.get("title", "Finding"),
            message=event.get("description", ""),
            severity=severity,
            fields=[
                {"name": "Severity", "value": severity, "short": True},
                {"name": "Module", "value": event.get("module", ""), "short": True},
                {"name": "URL", "value": event.get("url", ""), "short": False},
            ],
        )
