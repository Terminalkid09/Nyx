"""BUG-05: subscribers must never see an id whose row is not committed."""
import asyncio
import uuid

import pytest
from sqlalchemy import delete

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.finding_events import persist_results
from core.storage.models import Finding, Session
from modules.scanner.base_check import CheckResult


@pytest.mark.asyncio
async def test_event_published_after_commit():
    bus = EventBus()
    seen: dict = {}
    sid = uuid.uuid4()

    async with AsyncSessionLocal() as db:
        db.add(Session(id=sid, name=f"finding-events-{sid}"))
        await db.commit()

    async def handler(event: dict):
        async with AsyncSessionLocal() as db:
            row = await db.get(Finding, uuid.UUID(event["id"]))
        seen["found"] = row is not None
        seen["severity"] = event["severity"]
        seen["param_source"] = event.get("source")

    bus.subscribe("finding.created", handler)

    result = CheckResult(
        triggered=True,
        severity="high",
        title="SQL Injection",
        description="id is injectable",
        cwe="CWE-89",
        param="id",
    )
    try:
        await persist_results(
            bus,
            [result],
            {"session_id": str(sid), "request_id": None},
            "active_sqli",
            source="active",
        )
        await asyncio.sleep(0.2)
        assert seen.get("found") is True
        assert seen.get("severity") == "high"
        assert seen.get("param_source") == "active"
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Finding).where(Finding.session_id == sid))
            await db.execute(delete(Session).where(Session.id == sid))
            await db.commit()
