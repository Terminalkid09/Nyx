"""Rules of Engagement (F-01).

An engagement is only defensible if the tool can prove, at the moment it sends
a probe, that the target was authorized. This module holds the signed policy
format, the matcher and the rate gate; ``authorize_url`` is the single entry
point used by the scanners.

Signing uses HMAC-SHA256 with the process secret. It is not a PKI signature:
it makes silent row edits detectable (an operator with DB write access is not
the threat model), and it gives the audit/report layer a verifiable artifact.
"""
import asyncio
import fnmatch
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select

from core.config import settings
from core.storage.database import AsyncSessionLocal
from core.storage.models import AuthorizationProfile

# Field set covered by the HMAC. ``active`` is deliberately excluded: it is a
# reversible operational switch, not an engagement term, and the API is the
# supported way to flip it.
_SIGNED_FIELDS = ("name", "targets", "exclusions", "window_start", "window_end", "max_rps")


@dataclass(frozen=True)
class RoEPolicy:
    id: str
    name: str
    targets: tuple[str, ...]
    exclusions: tuple[str, ...]
    window_start: datetime | None
    window_end: datetime | None
    max_rps: float
    signature: str


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical(fields: dict) -> str:
    payload = {}
    for key in _SIGNED_FIELDS:
        value = fields.get(key)
        if isinstance(value, datetime):
            # SQLite returns naive datetimes even for DateTime(timezone=True),
            # while API input can be aware. Canonicalize both to UTC before
            # serializing: otherwise the same policy signs differently after a
            # DB round-trip and every timed profile fails verification.
            value = _as_utc(value)
            value = value.isoformat() if value is not None else None
        payload[key] = value
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def sign_policy(secret: str, **fields) -> str:
    """Return the hex signature for the signed subset of a policy."""
    return hmac.new(
        secret.encode("utf-8"), _canonical(fields).encode("utf-8"), hashlib.sha256
    ).hexdigest()


def policy_from_model(row: AuthorizationProfile) -> RoEPolicy:
    return RoEPolicy(
        id=str(row.id),
        name=row.name,
        targets=tuple(row.targets or ()),
        exclusions=tuple(row.exclusions or ()),
        window_start=_as_utc(row.window_start),
        window_end=_as_utc(row.window_end),
        max_rps=float(row.max_rps or 0.0),
        signature=row.signature or "",
    )


def verify_policy(policy: RoEPolicy, secret: str) -> bool:
    expected = sign_policy(
        secret,
        name=policy.name,
        targets=list(policy.targets),
        exclusions=list(policy.exclusions),
        window_start=policy.window_start,
        window_end=policy.window_end,
        max_rps=policy.max_rps,
    )
    return hmac.compare_digest(expected, policy.signature)


def _match(value: str, pattern: str) -> bool:
    if pattern.startswith("re:"):
        try:
            return bool(re.search(pattern[3:], value))
        except re.error:
            return False
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def policy_allows(
    policy: RoEPolicy, url: str, now: datetime | None = None
) -> tuple[bool, str | None]:
    """Return (allowed, reason). Reasons are stable, machine-readable strings."""
    now = _as_utc(now) or datetime.now(timezone.utc)

    start = _as_utc(policy.window_start)
    end = _as_utc(policy.window_end)
    if start and now < start:
        return False, "outside_window"
    if end and now > end:
        return False, "outside_window"

    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False, "invalid_url"

    for pattern in policy.exclusions:
        if _match(host, pattern) or _match(url, pattern):
            return False, "excluded"

    if not policy.targets:
        return False, "no_targets"

    for pattern in policy.targets:
        if _match(host, pattern) or _match(url, pattern):
            return True, None
    return False, "not_targeted"


_gate_lock = asyncio.Lock()
_next_slot: dict[str, float] = {}

# The rate lookup runs once per outbound probe in loops that can issue
# thousands of requests (content discovery, fuzzing). Reloading the policy
# rows from SQLite for each one dominated the request cost, so the signed
# policy list is cached briefly. A policy change takes effect within the TTL.
_RATE_CACHE_TTL_SECONDS = 5.0
_rate_cache: tuple[float, tuple[RoEPolicy, ...]] = (0.0, ())
_rate_cache_lock = asyncio.Lock()


async def _signed_policies() -> tuple[RoEPolicy, ...]:
    """Return the active policies with a valid signature (cached)."""
    global _rate_cache
    now = time.monotonic()
    cached_at, cached = _rate_cache
    if now - cached_at < _RATE_CACHE_TTL_SECONDS:
        return cached
    async with _rate_cache_lock:
        cached_at, cached = _rate_cache
        if time.monotonic() - cached_at < _RATE_CACHE_TTL_SECONDS:
            return cached
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(AuthorizationProfile).where(AuthorizationProfile.active.is_(True))
            )
            rows = list(result.scalars().all())
        policies = tuple(
            policy
            for policy in (policy_from_model(row) for row in rows)
            if verify_policy(policy, settings.secret_key)
        )
        _rate_cache = (time.monotonic(), policies)
        return policies


def invalidate_rate_cache() -> None:
    """Force the next rate lookup to reload profiles (used by the RoE API)."""
    global _rate_cache
    _rate_cache = (0.0, ())


async def acquire_rate_slot(policy_id: str, max_rps: float) -> None:
    """Global per-policy pacing. max_rps <= 0 means unlimited."""
    if max_rps <= 0:
        return
    interval = 1.0 / max_rps
    async with _gate_lock:
        now = time.monotonic()
        slot = max(now, _next_slot.get(policy_id, now))
        _next_slot[policy_id] = slot + interval
        wait = slot - now
    if wait > 0:
        await asyncio.sleep(wait)


async def rate_limit_for(url: str) -> tuple[str, float] | None:
    """Return (policy_id, max_rps) for a URL, or None when unpaced."""
    for policy in await _signed_policies():
        if policy.max_rps <= 0:
            continue
        allowed, _reason = policy_allows(policy, url)
        if allowed:
            return policy.id, policy.max_rps
    return None


async def pace(url: str) -> None:
    """Wait for the next rate slot of the RoE policy covering ``url``.

    Every component that emits probes (scanner checks, content discovery,
    fuzzing) calls this before a request so a signed ``max_rps`` is a real
    ceiling instead of documentation.
    """
    limit = await rate_limit_for(url)
    if limit:
        await acquire_rate_slot(*limit)


async def authorize_url(url: str, now: datetime | None = None) -> tuple[bool, str | None]:
    """Check an outbound probe against every active, correctly signed profile.

    Returns (True, profile name) when authorized. With no profiles configured
    the tool keeps working as before (True, None). Rate limiting is a separate
    concern: call :func:`pace` immediately before the request so authorization
    and pacing are not applied twice.
    """
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AuthorizationProfile).where(AuthorizationProfile.active.is_(True))
        )
        rows = list(result.scalars().all())

    if not rows:
        return True, None

    signature_seen = False
    for row in rows:
        policy = policy_from_model(row)
        if not verify_policy(policy, settings.secret_key):
            continue
        signature_seen = True
        allowed, _reason = policy_allows(policy, url, now=now)
        if allowed:
            return True, policy.name
    return False, "no_authorization_profile" if signature_seen else "invalid_signature"
