"""BUG-06: the fuzzer must honour scope/RoE before sending payloads."""
import uuid

import pytest
from sqlalchemy import delete, select

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import FuzzJob, FuzzResult, Request, Session
from modules.fuzzer.service import FuzzerService

TEMPLATE = "GET /?id=1 HTTP/1.1\r\nHost: blocked.example\r\n\r\n"


@pytest.mark.asyncio
async def test_out_of_scope_job_is_cancelled_without_requests(monkeypatch):
    sid = uuid.uuid4()
    rid = uuid.uuid4()
    async with AsyncSessionLocal() as db:
        db.add(Session(id=sid, name=f"fuzz-scope-{sid}"))
        await db.flush()
        db.add(Request(
            id=rid, session_id=sid, method="GET",
            url="https://blocked.example/?id=1", host="blocked.example",
            path="/", request_headers={},
        ))
        job = FuzzJob(
            session_id=sid, base_request_id=rid, request_template=TEMPLATE,
            attack_type="sniper", wordlist_name="tiny", positions=[],
            grep_matches=[], extractors=[], status="pending", total_requests=0,
        )
        db.add(job)
        await db.commit()
        job_id = job.id

    async def deny(session_id, url):
        return False, "roe", "no_authorization_profile"

    monkeypatch.setattr("core.authorization.authorize", deny)

    service = FuzzerService(EventBus())
    try:
        await service.run_job(
            job_id=job_id, template=TEMPLATE, positions=[],
            wordlists={}, attack_type="sniper", processors=[],
            grep_matches=[], extractors=[], rate_limit_rps=10,
        )
        async with AsyncSessionLocal() as db:
            stored = await db.get(FuzzJob, job_id)
            assert stored.status == "cancelled"
            rows = (await db.execute(
                select(FuzzResult).where(FuzzResult.job_id == job_id)
            )).scalars().all()
            assert "not authorized" in rows[0].error
    finally:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(FuzzResult).where(FuzzResult.job_id == job_id))
            await db.execute(delete(FuzzJob).where(FuzzJob.id == job_id))
            await db.execute(delete(Request).where(Request.id == rid))
            await db.execute(delete(Session).where(Session.id == sid))
            await db.commit()
