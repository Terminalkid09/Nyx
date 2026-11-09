"""BUG-04 fase B: fuzzer results live in ``fuzz_results``, not in a JSON blob.

Covers the writer (one row per payload, flushed during the run) and the reader
(``GET /api/fuzzer/jobs/{id}/results``), including the legacy fallback for jobs
created before the table existed.
"""
import uuid
from datetime import timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from main import app
from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import FuzzJob, FuzzResult, Request, Session
from modules.fuzzer.service import FuzzerService

TEMPLATE = "GET /?q=\u00a7x\u00a7 HTTP/1.1\r\nHost: 127.0.0.1:8099\r\n\r\n"


class _FakeResponse:
    status_code = 200
    reason_phrase = "OK"
    headers = {"content-type": "text/plain"}
    text = "hello from the target"
    content = b"hello from the target"
    elapsed = timedelta(milliseconds=5)


class _FakeClient:
    """Stands in for httpx.AsyncClient: the service never touches the network."""

    closed = False

    def __init__(self, *args, **kwargs):
        pass

    async def request(self, **kwargs):
        return _FakeResponse()

    async def aclose(self):
        _FakeClient.closed = True


async def _seed_job(wordlist_name: str = "tiny") -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    """Create session + captured request + fuzz job; return their ids."""
    sid, rid = uuid.uuid4(), uuid.uuid4()
    async with AsyncSessionLocal() as db:
        db.add(Session(id=sid, name=f"fuzz-results-{sid}"))
        await db.flush()
        db.add(Request(
            id=rid, session_id=sid, method="GET",
            url="http://127.0.0.1:8099/?q=1", host="127.0.0.1:8099",
            path="/", request_headers={},
        ))
        job = FuzzJob(
            session_id=sid, base_request_id=rid, request_template=TEMPLATE,
            attack_type="sniper", wordlist_name=wordlist_name, positions=[],
            grep_matches=[], extractors=[], status="pending", total_requests=0,
        )
        db.add(job)
        await db.commit()
        return sid, rid, job.id


async def _cleanup(sid: uuid.UUID, rid: uuid.UUID, job_id: uuid.UUID | None = None) -> None:
    async with AsyncSessionLocal() as db:
        if job_id is not None:
            await db.execute(delete(FuzzResult).where(FuzzResult.job_id == job_id))
            await db.execute(delete(FuzzJob).where(FuzzJob.id == job_id))
        await db.execute(delete(FuzzJob).where(FuzzJob.session_id == sid))
        await db.execute(delete(Request).where(Request.id == rid))
        await db.execute(delete(Session).where(Session.id == sid))
        await db.commit()


@pytest.mark.asyncio
async def test_job_writes_one_row_per_payload(monkeypatch):
    sid, rid, job_id = await _seed_job()

    async def allow(*args, **kwargs):
        return True, "roe", "allowed"

    async def no_pace(*args, **kwargs):
        return None

    monkeypatch.setattr("core.authorization.authorize", allow)
    monkeypatch.setattr("core.roe.pace", no_pace)
    monkeypatch.setattr("modules.fuzzer.service.httpx.AsyncClient", _FakeClient)

    service = FuzzerService(EventBus())
    try:
        await service.run_job(
            job_id=job_id, template=TEMPLATE,
            positions=[{"name": "x", "processors": []}],
            wordlists={"x": ["1", "2", "3"]},
            attack_type="sniper", processors=[],
            grep_matches=[], extractors=[], rate_limit_rps=0,
        )
        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            assert job.status == "done"
            assert job.completed_requests == 3
            # The JSON blob is no longer written.
            assert job.results == []

            rows = (await db.execute(
                select(FuzzResult).where(FuzzResult.job_id == job_id).order_by(FuzzResult.seq)
            )).scalars().all()
            assert [r.seq for r in rows] == [0, 1, 2]
            assert [r.payload["x"] for r in rows] == ["1", "2", "3"]
            assert all(r.status == 200 for r in rows)
            assert all("hello from the target" in (r.response or "") for r in rows)
            assert all(r.request.startswith("GET /?q=") for r in rows)
    finally:
        await _cleanup(sid, rid, job_id)


@pytest.mark.asyncio
async def test_excluded_payload_url_is_not_sent(monkeypatch):
    sid, rid, job_id = await _seed_job()
    auth_calls = []
    sent = []

    async def conditional(session_id, url):
        auth_calls.append(url)
        # First call is the job-level template check; every concrete payload
        # that follows is outside the engagement.
        if len(auth_calls) == 1:
            return True, "roe", "allowed"
        return False, "roe", "excluded"

    class RecordingClient(_FakeClient):
        async def request(self, **kwargs):
            sent.append(kwargs)
            return _FakeResponse()

    async def no_pace(*args, **kwargs):
        return None

    monkeypatch.setattr("core.authorization.authorize", conditional)
    monkeypatch.setattr("core.roe.pace", no_pace)
    monkeypatch.setattr(
        "modules.fuzzer.service.httpx.AsyncClient", RecordingClient
    )

    service = FuzzerService(EventBus())
    try:
        await service.run_job(
            job_id=job_id, template=TEMPLATE,
            positions=[{"name": "x", "processors": []}],
            wordlists={"x": ["1", "2"]},
            attack_type="sniper", processors=[],
            grep_matches=[], extractors=[], rate_limit_rps=0,
        )
        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            assert job.status == "done"
            rows = (await db.execute(
                select(FuzzResult)
                .where(FuzzResult.job_id == job_id)
                .order_by(FuzzResult.seq)
            )).scalars().all()
            assert len(rows) == 2
            assert all("not authorized" in (row.error or "") for row in rows)
        assert sent == []
    finally:
        await _cleanup(sid, rid, job_id)


@pytest.mark.asyncio
async def test_results_endpoint_serves_rows_and_filters(monkeypatch):
    sid, rid, job_id = await _seed_job()
    try:
        async with AsyncSessionLocal() as db:
            db.add_all([
                FuzzResult(job_id=job_id, seq=0, payload={"x": "a"}, status=200,
                           size=3, time_ms=4, grep_results={}, extracted={},
                           request="GET /?q=a HTTP/1.1\r\nHost: h\r\n\r\n",
                           response="HTTP/1.1 200 OK\r\n\r\nabc"),
                FuzzResult(job_id=job_id, seq=1, payload={"x": "b"}, status=500,
                           size=0, time_ms=9, grep_results={}, extracted={},
                           request="GET /?q=b HTTP/1.1\r\nHost: h\r\n\r\n",
                           response="HTTP/1.1 500 OK\r\n\r\n"),
            ])
            await db.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            everything = await client.get(f"/api/fuzzer/jobs/{job_id}/results")
            assert everything.status_code == 200, everything.text
            assert [r["payload"]["x"] for r in everything.json()] == ["a", "b"]

            only_500 = await client.get(
                f"/api/fuzzer/jobs/{job_id}/results", params={"status_filter": 500}
            )
            assert [r["status"] for r in only_500.json()] == [500]

            paged = await client.get(
                f"/api/fuzzer/jobs/{job_id}/results", params={"limit": 1, "offset": 1}
            )
            assert [r["payload"]["x"] for r in paged.json()] == ["b"]
    finally:
        await _cleanup(sid, rid, job_id)


@pytest.mark.asyncio
async def test_results_endpoint_still_serves_legacy_jobs():
    sid, rid, job_id = await _seed_job()
    try:
        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            job.results = [{"payload": {"x": "old"}, "status": 200, "request": "raw"}]
            await db.commit()

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get(f"/api/fuzzer/jobs/{job_id}/results")
        assert response.status_code == 200
        assert response.json()[0]["payload"] == {"x": "old"}
    finally:
        await _cleanup(sid, rid, job_id)


@pytest.mark.asyncio
async def test_deleting_session_removes_fuzz_results():
    from core.storage.crud.sessions import delete_session

    sid, rid, job_id = await _seed_job()
    try:
        async with AsyncSessionLocal() as db:
            db.add(FuzzResult(job_id=job_id, seq=0, payload={"x": "a"}, status=200,
                              grep_results={}, extracted={}))
            await db.commit()

        async with AsyncSessionLocal() as db:
            assert await delete_session(db, sid) is True
            remaining = (await db.execute(
                select(FuzzResult).where(FuzzResult.job_id == job_id)
            )).scalars().all()
            assert remaining == []
    finally:
        await _cleanup(sid, rid, job_id)
