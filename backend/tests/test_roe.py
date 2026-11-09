"""F-01: signed Rules of Engagement."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete

from core.config import settings
from core.roe import (
    RoEPolicy,
    authorize_url,
    policy_allows,
    policy_from_model,
    sign_policy,
    verify_policy,
)
from core.storage.database import AsyncSessionLocal
from core.storage.models import AuthorizationProfile


def make_policy(**overrides) -> RoEPolicy:
    fields = {
        "name": "engagement",
        "targets": ("example.com",),
        "exclusions": ("admin.example.com",),
        "window_start": None,
        "window_end": None,
        "max_rps": 0.0,
    }
    fields.update(overrides)
    signature = sign_policy(settings.secret_key, **fields)
    return RoEPolicy(id="test", signature=signature, **fields)


class TestSigning:
    def test_roundtrip(self):
        assert verify_policy(make_policy(), settings.secret_key) is True

    def test_tampered_targets_fail(self):
        policy = make_policy()
        tampered = RoEPolicy(
            id=policy.id, name=policy.name, targets=("evil.example",),
            exclusions=policy.exclusions, window_start=policy.window_start,
            window_end=policy.window_end, max_rps=policy.max_rps,
            signature=policy.signature,
        )
        assert verify_policy(tampered, settings.secret_key) is False

    def test_wrong_secret_fails(self):
        assert verify_policy(make_policy(), "another-secret") is False

    def test_naive_and_aware_windows_sign_the_same(self):
        # SQLite returns naive datetimes for DateTime(timezone=True), while the
        # API parses an explicit offset as aware. Both encode the same instant
        # and must produce the same signature after canonicalization.
        aware = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        naive = datetime(2026, 1, 1, 12, 0)
        common = {
            "name": "timed",
            "targets": ["example.com"],
            "exclusions": [],
            "max_rps": 0.0,
        }
        assert sign_policy(
            settings.secret_key, window_start=aware, window_end=aware, **common
        ) == sign_policy(
            settings.secret_key, window_start=naive, window_end=naive, **common
        )


class TestPolicyAllows:
    def test_matching_host(self):
        allowed, reason = policy_allows(make_policy(), "https://example.com/a")
        assert allowed is True and reason is None

    def test_non_matching_host(self):
        allowed, reason = policy_allows(make_policy(), "https://other.example/a")
        assert allowed is False and reason == "not_targeted"

    def test_exclusion_wins(self):
        allowed, reason = policy_allows(
            make_policy(), "https://admin.example.com/"
        )
        assert allowed is False and reason == "excluded"

    def test_window(self):
        now = datetime.now(timezone.utc)
        policy = make_policy(
            window_start=now - timedelta(hours=1),
            window_end=now + timedelta(hours=1),
        )
        assert policy_allows(policy, "https://example.com/", now=now)[0] is True
        assert policy_allows(
            policy, "https://example.com/", now=now + timedelta(hours=2)
        ) == (False, "outside_window")

    def test_empty_targets_authorizes_nothing(self):
        assert policy_allows(make_policy(targets=()), "https://example.com/") == (
            False, "no_targets"
        )

    def test_regex_target(self):
        policy = make_policy(targets=("re:^api\\d*\\.example\\.com$",))
        assert policy_allows(policy, "https://api2.example.com/")[0] is True


@pytest.mark.asyncio
async def test_authorize_url_uses_active_profile():
    fields = {
        "name": "integration-roe",
        "targets": ["allowed.example"],
        "exclusions": [],
        "window_start": None,
        "window_end": None,
        "max_rps": 0.0,
    }
    signature = sign_policy(settings.secret_key, **fields)
    async with AsyncSessionLocal() as db:
        row = AuthorizationProfile(signature=signature, active=True, **fields)
        db.add(row)
        await db.commit()
        profile_id = row.id

    try:
        allowed, name = await authorize_url("https://allowed.example/x")
        assert allowed is True and name == "integration-roe"

        allowed, reason = await authorize_url("https://other.example/x")
        assert allowed is False and reason == "no_authorization_profile"
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(AuthorizationProfile).where(AuthorizationProfile.id == profile_id)
            )
            await db.commit()


@pytest.mark.asyncio
async def test_timed_profile_survives_database_roundtrip():
    """A windowed profile must still verify after SQLite reloads it.

    Regression: SQLite returns naive datetimes even for DateTime(timezone=True).
    The canonical form used for signing included the offset, so a signed
    aware datetime no longer matched after reload and every timed profile was
    rejected as invalid_signature.
    """
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fields = {
        "name": "timed-roe",
        "targets": ["allowed.example"],
        "exclusions": [],
        "window_start": now - timedelta(hours=1),
        "window_end": now + timedelta(hours=1),
        "max_rps": 0.0,
    }
    signature = sign_policy(settings.secret_key, **fields)
    async with AsyncSessionLocal() as db:
        row = AuthorizationProfile(signature=signature, active=True, **fields)
        db.add(row)
        await db.commit()
        profile_id = row.id

    try:
        async with AsyncSessionLocal() as db:
            stored = await db.get(AuthorizationProfile, profile_id)
            assert stored is not None
            assert verify_policy(
                policy_from_model(stored), settings.secret_key
            ) is True

        allowed, name = await authorize_url("https://allowed.example/x", now=now)
        assert allowed is True and name == "timed-roe"
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(AuthorizationProfile).where(AuthorizationProfile.id == profile_id)
            )
            await db.commit()


@pytest.mark.asyncio
async def test_signed_policy_cache_expires(monkeypatch):
    """The cache must expire instead of short-circuiting on a non-empty tuple."""
    import core.roe as roe

    policy = make_policy()
    roe._rate_cache = (100.0, (policy,))
    queries = []

    class _Result:
        def scalars(self):
            return self

        def all(self):
            return []

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def execute(self, _statement):
            queries.append(1)
            return _Result()

    monkeypatch.setattr(roe, "AsyncSessionLocal", lambda: _Session())

    try:
        monkeypatch.setattr(roe.time, "monotonic", lambda: 101.0)
        assert await roe._signed_policies() == (policy,)
        assert queries == []

        monkeypatch.setattr(roe.time, "monotonic", lambda: 110.0)
        assert await roe._signed_policies() == ()
        assert queries == [1]
    finally:
        roe.invalidate_rate_cache()


@pytest.mark.asyncio
async def test_authorize_url_rejects_tampered_profile():
    fields = {
        "name": "tampered-roe",
        "targets": ["allowed.example"],
        "exclusions": [],
        "window_start": None,
        "window_end": None,
        "max_rps": 0.0,
    }
    signature = sign_policy(settings.secret_key, **fields)
    async with AsyncSessionLocal() as db:
        row = AuthorizationProfile(signature=signature, active=True, **fields)
        db.add(row)
        await db.commit()
        profile_id = row.id
        row.targets = ["*"]
        await db.commit()

    try:
        allowed, reason = await authorize_url("https://anything.example/x")
        assert allowed is False and reason == "invalid_signature"
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(AuthorizationProfile).where(AuthorizationProfile.id == profile_id)
            )
            await db.commit()


@pytest.mark.asyncio
async def test_pace_uses_the_covering_policy(monkeypatch):
    import time as _time

    import core.roe as roe

    policy = make_policy(targets=("example.com",), max_rps=2.0)
    roe._rate_cache = (_time.monotonic(), (policy,))
    calls = []

    async def fake_slot(policy_id, rps):
        calls.append((policy_id, rps))

    monkeypatch.setattr(roe, "acquire_rate_slot", fake_slot)
    try:
        await roe.pace("https://example.com/page")
        await roe.pace("https://other.example/page")
    finally:
        roe.invalidate_rate_cache()

    assert calls == [(policy.id, 2.0)]


@pytest.mark.asyncio
async def test_roe_api_update_and_delete():
    from httpx import ASGITransport, AsyncClient

    from main import app

    payload = {
        "name": "api-roe",
        "targets": ["old.example"],
        "exclusions": [],
        "max_rps": 0.0,
    }
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        created = await client.post("/api/roe", json=payload)
        assert created.status_code == 201, created.text
        profile = created.json()
        assert profile["signature_valid"] is True

        # Editing the engagement terms must re-sign the row.
        updated = await client.put(
            f"/api/roe/{profile['id']}",
            json={**payload, "targets": ["new.example"]},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["targets"] == ["new.example"]
        assert updated.json()["signature_valid"] is True

        # Deactivation is operational state and survives a content edit.
        deactivated = await client.post(f"/api/roe/{profile['id']}/deactivate")
        assert deactivated.status_code == 200
        updated_again = await client.put(
            f"/api/roe/{profile['id']}",
            json={**payload, "targets": ["new.example"], "max_rps": 1.0},
        )
        assert updated_again.json()["active"] is False
        assert updated_again.json()["signature_valid"] is True

        deleted = await client.delete(f"/api/roe/{profile['id']}")
        assert deleted.status_code == 204
        missing = await client.get(f"/api/roe/{profile['id']}")
        assert missing.status_code == 404


@pytest.mark.asyncio
async def test_unlimited_policy_does_not_pace(monkeypatch):
    import time as _time

    import core.roe as roe

    policy = make_policy(targets=("example.com",), max_rps=0.0)
    roe._rate_cache = (_time.monotonic(), (policy,))
    calls = []

    async def fake_slot(policy_id, rps):
        calls.append((policy_id, rps))

    monkeypatch.setattr(roe, "acquire_rate_slot", fake_slot)
    try:
        await roe.pace("https://example.com/page")
    finally:
        roe.invalidate_rate_cache()

    assert calls == []
