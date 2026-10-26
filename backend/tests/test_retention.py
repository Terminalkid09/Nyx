"""BUG-01: retention must order by timestamp, not by uuid4."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from core.storage.database import AsyncSessionLocal
from core.storage.models import Request, Session
from core.storage.traffic import TrafficStorageService


@pytest.mark.asyncio
async def test_retention_keeps_newest_by_timestamp():
    sid = uuid.uuid4()
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add(Session(id=sid, name=f"retention-{sid}"))
        await db.flush()
        for i in range(10):
            db.add(Request(
                id=uuid.uuid4(),
                session_id=sid,
                timestamp=now - timedelta(minutes=10 - i),
                method="GET",
                url=f"http://example.com/{i}",
                host="example.com",
                path=f"/{i}",
                request_headers={},
            ))
        await db.commit()

    try:
        await TrafficStorageService._purge_old_requests(max_req=5, max_hours=0)

        async with AsyncSessionLocal() as db:
            rows = (
                await db.execute(
                    select(Request.path)
                    .where(Request.session_id == sid)
                    .order_by(Request.timestamp)
                )
            ).scalars().all()
        assert rows == ["/5", "/6", "/7", "/8", "/9"]
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Request).where(Request.session_id == sid))
            await db.execute(delete(Session).where(Session.id == sid))
            await db.commit()


@pytest.mark.asyncio
async def test_retention_noop_below_cap():
    sid = uuid.uuid4()
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add(Session(id=sid, name=f"retention-noop-{sid}"))
        await db.flush()
        for i in range(3):
            db.add(Request(
                id=uuid.uuid4(), session_id=sid,
                timestamp=now - timedelta(minutes=i),
                method="GET", url=f"http://example.com/{i}",
                host="example.com", path=f"/{i}", request_headers={},
            ))
        await db.commit()

    try:
        await TrafficStorageService._purge_old_requests(max_req=10, max_hours=0)
        async with AsyncSessionLocal() as db:
            count = len((
                await db.execute(select(Request.id).where(Request.session_id == sid))
            ).scalars().all())
        assert count == 3
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(Request).where(Request.session_id == sid))
            await db.execute(delete(Session).where(Session.id == sid))
            await db.commit()
