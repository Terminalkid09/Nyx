import json
import logging
import os
from datetime import datetime, timezone

from modules.auth.models import AuthProfile

logger = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
AUTH_PROFILES_FILE = os.path.join(DATA_DIR, "auth_profiles.json")


def _ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def _load_profiles() -> dict[str, dict]:
    _ensure_data_dir()
    if not os.path.exists(AUTH_PROFILES_FILE):
        return {}
    try:
        with open(AUTH_PROFILES_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load auth profiles: %s", e)
        return {}


def _save_profiles(profiles: dict[str, dict]):
    _ensure_data_dir()
    with open(AUTH_PROFILES_FILE, "w") as f:
        json.dump(profiles, f, indent=2, default=str)


def list_profiles() -> list[AuthProfile]:
    raw = _load_profiles()
    return [AuthProfile(**p) for p in raw.values()]


def get_profile(profile_id: str) -> AuthProfile | None:
    raw = _load_profiles()
    data = raw.get(profile_id)
    return AuthProfile(**data) if data else None


def create_profile(profile: AuthProfile) -> AuthProfile:
    import uuid
    profile.id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    profile.created_at = now
    profile.updated_at = now
    raw = _load_profiles()
    raw[profile.id] = profile.model_dump()
    _save_profiles(raw)
    return profile


def update_profile(profile_id: str, profile: AuthProfile) -> AuthProfile | None:
    raw = _load_profiles()
    if profile_id not in raw:
        return None
    profile.id = profile_id
    profile.updated_at = datetime.now(timezone.utc).isoformat()
    raw[profile_id] = profile.model_dump()
    _save_profiles(raw)
    return profile


def delete_profile(profile_id: str) -> bool:
    raw = _load_profiles()
    if profile_id not in raw:
        return False
    del raw[profile_id]
    _save_profiles(raw)
    return True
