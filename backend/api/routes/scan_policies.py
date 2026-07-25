import uuid
import json
from pathlib import Path
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/api/scan-policies", tags=["scan-policies"])

POLICIES_PATH = Path(__file__).parent.parent.parent / "data" / "scan_policies.json"


def _load() -> list[dict]:
    if POLICIES_PATH.exists():
        try:
            return json.loads(POLICIES_PATH.read_text())
        except Exception:
            return []
    return []


def _save(policies: list[dict]):
    POLICIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICIES_PATH.write_text(json.dumps(policies, indent=2))


_defaults = [
    {
        "id": "policy-standard",
        "name": "Standard Scan",
        "description": "Balanced scan — crawl up to 50 pages, passive + active checks, no fuzzing",
        "priority": 5,
        "config": {
            "crawl": {"max_pages": 50, "max_depth": 3, "respect_robots_txt": True},
            "discovery": {"enabled": False},
            "fuzz": {"enabled": False},
            "passive_scan": {"enabled": True},
            "active_scan": {"enabled": True, "max_checks": 50},
            "notify_on_complete": True,
        },
    },
    {
        "id": "policy-thorough",
        "name": "Thorough Scan",
        "description": "Full coverage — crawl + discovery + fuzz + all active checks",
        "priority": 8,
        "config": {
            "crawl": {"max_pages": 200, "max_depth": 5, "respect_robots_txt": True},
            "discovery": {"enabled": True, "wordlist_path": "content_discovery.txt"},
            "fuzz": {"enabled": True, "attack_type": "sniper", "rate_limit": 10},
            "passive_scan": {"enabled": True},
            "active_scan": {"enabled": True, "max_checks": 200},
            "notify_on_complete": True,
        },
    },
    {
        "id": "policy-quick",
        "name": "Quick Check",
        "description": "Minimal footprint — 5 page crawl, passive scan only",
        "priority": 2,
        "config": {
            "crawl": {"max_pages": 5, "max_depth": 1, "respect_robots_txt": True},
            "discovery": {"enabled": False},
            "fuzz": {"enabled": False},
            "passive_scan": {"enabled": True},
            "active_scan": {"enabled": False},
            "notify_on_complete": False,
        },
    },
    {
        "id": "policy-api",
        "name": "API Security Scan",
        "description": "No crawl, API-focused checks + fuzzing of JSON/XML endpoints",
        "priority": 7,
        "config": {
            "crawl": {"enabled": False},
            "discovery": {"enabled": True, "extensions": [".json", ".xml", ".graphql"]},
            "fuzz": {"enabled": True, "attack_type": "clusterbomb", "rate_limit": 5},
            "passive_scan": {"enabled": True},
            "active_scan": {"enabled": True, "max_checks": 100},
            "notify_on_complete": True,
        },
    },
]


@router.get("")
async def list_policies():
    policies = _load()
    if not policies:
        _save(_defaults)
        return _defaults
    return policies


@router.post("")
async def create_policy(policy: dict):
    policies = _load()
    policy["id"] = str(uuid.uuid4())
    policy["created_at"] = datetime.now(timezone.utc).isoformat()
    policies.append(policy)
    _save(policies)
    return policy


@router.get("/{policy_id}")
async def get_policy(policy_id: str):
    policies = _load()
    for p in policies:
        if p["id"] == policy_id:
            return p
    raise HTTPException(404, detail="Policy not found")


@router.put("/{policy_id}")
async def update_policy(policy_id: str, data: dict):
    policies = _load()
    for p in policies:
        if p["id"] == policy_id:
            p.update(data)
            _save(policies)
            return p
    raise HTTPException(404, detail="Policy not found")


@router.delete("/{policy_id}")
async def delete_policy(policy_id: str):
    policies = _load()
    new_policies = [p for p in policies if p["id"] != policy_id]
    if len(new_policies) == len(policies):
        raise HTTPException(404, detail="Policy not found")
    _save(new_policies)
    return {"detail": "Policy deleted"}
