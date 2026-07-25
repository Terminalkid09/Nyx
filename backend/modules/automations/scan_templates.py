import json
import uuid
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class ScanTemplateService:
    def __init__(self):
        self._templates_path = Path(__file__).parent.parent.parent / "data" / "scan_templates.json"
        self._templates = []
        self._load()

    def _load(self):
        if self._templates_path.exists():
            try:
                self._templates = json.loads(self._templates_path.read_text())
            except Exception:
                self._templates = []
        else:
            self._templates = self._defaults()
            self._save()

    def _save(self):
        self._templates_path.parent.mkdir(parents=True, exist_ok=True)
        self._templates_path.write_text(json.dumps(self._templates, indent=2))

    def _defaults(self) -> list[dict]:
        return [
            {
                "id": "default-quick",
                "name": "Quick Scan",
                "description": "Fast crawl + passive scan (5 pages, no fuzz)",
                "config": {
                    "crawl": {"max_pages": 5, "max_depth": 2},
                    "discovery": {"enabled": False},
                    "fuzz": {"enabled": False},
                    "active_scan": {"enabled": True},
                },
            },
            {
                "id": "default-full",
                "name": "Full Scan",
                "description": "Crawl + discovery + fuzz + active scan on all endpoints",
                "config": {
                    "crawl": {"max_pages": 50, "max_depth": 3},
                    "discovery": {"enabled": True, "wordlist_path": "content_discovery.txt"},
                    "fuzz": {"enabled": True, "attack_type": "sniper"},
                    "active_scan": {"enabled": True},
                },
            },
            {
                "id": "default-api",
                "name": "API Scan",
                "description": "No crawl, direct discovery + fuzz on API endpoints",
                "config": {
                    "crawl": {"enabled": False},
                    "discovery": {"enabled": True, "extensions": [".json", ".xml"]},
                    "fuzz": {"enabled": True},
                    "active_scan": {"enabled": True},
                },
            },
        ]

    def list_templates(self) -> list[dict]:
        return self._templates

    def get_template(self, template_id: str) -> dict | None:
        return next((t for t in self._templates if t["id"] == template_id), None)

    def create_template(self, template: dict) -> dict:
        template["id"] = str(uuid.uuid4())
        template.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        self._templates.append(template)
        self._save()
        return template

    def update_template(self, template_id: str, data: dict) -> dict | None:
        for t in self._templates:
            if t["id"] == template_id:
                t.update(data)
                t["updated_at"] = datetime.now(timezone.utc).isoformat()
                self._save()
                return t
        return None

    def delete_template(self, template_id: str) -> bool:
        self._templates = [t for t in self._templates if t["id"] != template_id]
        self._save()
        return True
