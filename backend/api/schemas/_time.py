"""Shared datetime serialization for API schemas.

SQLite stores datetimes as naive UTC wall-clock, so models come back with
naive ``datetime`` values that Pydantic serializes without an offset. The
frontend (JS ``new Date(...)``) then parses them as *local* time and fresh
records show up as "2h ago" — which made MITM captures look like old data.
Tagging the value as UTC fixes parsing everywhere the helper is used.
"""
from datetime import datetime, timezone


def serialize_utc(value: datetime) -> str:
    if value is None:
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()
