import logging
import uuid
from datetime import datetime, timezone
from core.events.bus import EventBus

logger = logging.getLogger(__name__)

RECOMMENDATION_RULES = [
    {
        "id": "fuzz_param",
        "label": "Fuzz Parameter",
        "description": "Run the fuzzer on this parameter to discover hidden issues",
        "module": "fuzzer",
        "icon": "Zap",
        "category": "exploitation",
        "trigger_cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-943"],
        "min_severity": "medium",
        "priority": 70,
    },
    {
        "id": "generate_exploit",
        "label": "Generate Exploit",
        "description": "Generate exploit code for this vulnerability",
        "module": "auto_exploit",
        "icon": "Bug",
        "category": "exploitation",
        "trigger_cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-94", "CWE-611", "CWE-502", "CWE-918", "CWE-22"],
        "min_severity": "high",
        "priority": 80,
    },
    {
        "id": "active_scan_endpoint",
        "label": "Active Scan Endpoint",
        "description": "Run active security checks on this endpoint",
        "module": "active_scanner",
        "icon": "Shield",
        "category": "scanning",
        "trigger_cwes": None,
        "min_severity": "high",
        "priority": 65,
    },
    {
        "id": "crawl_endpoint",
        "label": "Crawl Endpoint",
        "description": "Spider this endpoint to discover more URLs and attack surface",
        "module": "crawler",
        "icon": "Search",
        "category": "discovery",
        "trigger_cwes": None,
        "min_severity": "high",
        "priority": 40,
    },
    {
        "id": "content_discovery",
        "label": "Discover Content",
        "description": "Run content discovery on this path to find hidden resources",
        "module": "content_discovery",
        "icon": "FolderOpen",
        "category": "discovery",
        "trigger_cwes": None,
        "min_severity": "high",
        "priority": 50,
    },
]

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


class RecommendationEngine:
    MAX_ACTIVE = 20

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._recommendations: list[dict] = []
        self._consumed_findings: set[str] = set()
        event_bus.subscribe("finding.created", self._on_finding_created)

    async def _on_finding_created(self, event: dict):
        finding_id = event.get("id", "")
        if finding_id in self._consumed_findings:
            return
        self._consumed_findings.add(finding_id)

        cwe = event.get("cwe") or ""
        severity = str(event.get("severity", "info")).lower()
        title = event.get("title", "Unknown finding")
        module = event.get("module", "unknown")
        finding_data = {
            "id": finding_id,
            "cwe": cwe,
            "severity": severity,
            "title": title,
            "module": module,
        }

        generated = 0
        for rule in RECOMMENDATION_RULES:
            if rule["trigger_cwes"] is not None and cwe not in rule["trigger_cwes"]:
                continue
            sev_score = SEVERITY_ORDER.get(severity, 0)
            min_sev = SEVERITY_ORDER.get(rule["min_severity"], 0)
            if sev_score < min_sev:
                continue

            rec = {
                "id": str(uuid.uuid4()),
                "rule_id": rule["id"],
                "label": rule["label"],
                "description": rule["description"],
                "module": rule["module"],
                "category": rule.get("category", "general"),
                "icon": rule["icon"],
                "priority": rule["priority"] + sev_score * 5,
                "finding": finding_data,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "dismissed": False,
                "executed": False,
            }
            self._recommendations.append(rec)
            generated += 1

        active = [r for r in self._recommendations if not r["dismissed"] and not r["executed"]]
        if len(active) > self.MAX_ACTIVE:
            excess = sorted(active, key=lambda r: r["priority"])[:len(active) - self.MAX_ACTIVE]
            dismiss_ids = {r["id"] for r in excess}
            for r in self._recommendations:
                if r["id"] in dismiss_ids:
                    r["dismissed"] = True

        if generated > 0:
            logger.debug("Generated %d recommendation(s) for finding %s", generated, finding_id)

    def get_recommendations(self, active_only: bool = True, limit: int = 50) -> list[dict]:
        recs = self._recommendations
        if active_only:
            recs = [r for r in recs if not r["dismissed"] and not r["executed"]]
        recs.sort(key=lambda r: r["priority"], reverse=True)
        return recs[:limit]

    def get_recommendations_grouped(self, active_only: bool = True, limit: int = 50):
        recs = self.get_recommendations(active_only=active_only, limit=limit)
        groups: dict[str, list[dict]] = {}
        for r in recs:
            cat = r.get("category", "general")
            groups.setdefault(cat, []).append(r)
        return groups

    def dismiss_recommendation(self, rec_id: str) -> bool:
        for r in self._recommendations:
            if r["id"] == rec_id:
                r["dismissed"] = True
                return True
        return False

    def mark_executed(self, rec_id: str) -> bool:
        for r in self._recommendations:
            if r["id"] == rec_id:
                r["executed"] = True
                return True
        return False

    def dismiss_all_for_finding(self, finding_id: str) -> int:
        count = 0
        for r in self._recommendations:
            if r["finding"]["id"] == finding_id and not r["dismissed"]:
                r["dismissed"] = True
                count += 1
        return count

    def get_stats(self) -> dict:
        active = [r for r in self._recommendations if not r["dismissed"] and not r["executed"]]
        by_rule: dict[str, int] = {}
        by_module: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for r in active:
            by_rule[r["rule_id"]] = by_rule.get(r["rule_id"], 0) + 1
            by_module[r["module"]] = by_module.get(r["module"], 0) + 1
            cat = r.get("category", "general")
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "total": len(active),
            "by_rule": by_rule,
            "by_module": by_module,
            "by_category": by_category,
        }
