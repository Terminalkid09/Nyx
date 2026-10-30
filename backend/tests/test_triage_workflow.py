"""Triage decisions: dismiss, re-rate, retest.

Findings used to be immutable: the only way to get a false positive out of a
report was to delete it, which also deleted the evidence. These tests pin the
replacement workflow — a status and an override on the finding — and the three
places that must honour it: the grouped list, the report and retest.
"""
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from core.storage.database import AsyncSessionLocal
from core.storage.models import Finding, Request, SeverityEnum
from main import app


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def _seed(severity: SeverityEnum = SeverityEnum.HIGH) -> tuple[str, str, str]:
    """Session + request + finding, returned as (session, request, finding)."""
    async with AsyncSessionLocal() as db:
        from core.storage.crud.sessions import create_session

        session = await create_session(db, name=f"triage-{uuid.uuid4().hex[:6]}")
        request = Request(
            session_id=session.id,
            method="GET",
            url="https://target.test/admin/users/1",
            host="target.test",
            path="/admin/users/1",
            request_headers={"Host": "target.test", "Cookie": "sid=abc"},
            request_body=None,
            response_status=200,
        )
        db.add(request)
        await db.flush()
        finding = Finding(
            session_id=session.id,
            request_id=request.id,
            module="scanner",
            severity=severity,
            title="IDOR on user profile",
            description="Another user's profile is readable by id.",
            evidence="HTTP 200 with another user's email",
            cwe="CWE-639",
        )
        db.add(finding)
        await db.commit()
        return str(session.id), str(request.id), str(finding.id)


@pytest.mark.asyncio
async def test_severity_override_shows_in_grouped_and_report(client):
    session_id, _request_id, finding_id = await _seed()

    async with client as c:
        patched = await c.patch(
            f"/api/triage/findings/{finding_id}",
            json={"severity": "low", "triage_status": "confirmed"},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["severity"] == "low"
        assert patched.json()["triage_status"] == "confirmed"

        grouped = await c.get(
            "/api/triage/findings/grouped", params={"session_id": session_id}
        )
        group = grouped.json()["groups"][0]
        assert group["severity"] == "low"
        assert group["severity_override"] == "low"
        assert group["finding_ids"] == [finding_id]

        report = await c.post(
            "/api/reports/generate",
            params={"session_id": session_id, "format": "json"},
        )
        assert report.status_code == 200, report.text
        payload = report.json()
        assert payload["by_severity"].get("low") == 1
        assert payload["by_severity"].get("high") is None


@pytest.mark.asyncio
async def test_false_positive_leaves_the_worklist_and_the_report(client):
    session_id, _request_id, finding_id = await _seed()

    async with client as c:
        dismissed = await c.patch(
            f"/api/triage/findings/{finding_id}", json={"triage_status": "false_positive"}
        )
        assert dismissed.status_code == 200, dismissed.text

        visible = await c.get(
            "/api/triage/findings/grouped", params={"session_id": session_id}
        )
        assert visible.json()["groups"] == []

        with_dismissed = await c.get(
            "/api/triage/findings/grouped",
            params={"session_id": session_id, "include_triaged": True},
        )
        groups = with_dismissed.json()["groups"]
        assert len(groups) == 1
        assert groups[0]["triage_status"] == "false_positive"

        report = await c.post(
            "/api/reports/generate",
            params={"session_id": session_id, "format": "json"},
        )
        assert report.status_code == 200, report.text
        assert report.json()["total_findings"] == 0


@pytest.mark.asyncio
async def test_invalid_severity_is_rejected(client):
    _session_id, _request_id, finding_id = await _seed()

    async with client as c:
        response = await c.patch(
            f"/api/triage/findings/{finding_id}", json={"severity": "catastrophic"}
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_retest_confirms_when_the_response_matches(client, monkeypatch):
    _session_id, _request_id, finding_id = await _seed()

    class _Response:
        status_code = 200
        content = b"still vulnerable"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, *args, **kwargs):
            return _Response()

    import api.routes.smart_triage as triage

    monkeypatch.setattr(triage, "authorize", lambda *a, **k: _allow())
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _Client())

    async with client as c:
        response = await c.get(f"/api/triage/findings/{finding_id}/retest")

    assert response.status_code == 200, response.text
    assert response.json()["result"] == "confirmed"
    assert response.json()["triage_status"] == "confirmed"

    async with AsyncSessionLocal() as db:
        finding = await db.get(Finding, uuid.UUID(finding_id))
        assert finding.triage_status == "confirmed"


@pytest.mark.asyncio
async def test_retest_asks_for_review_when_the_response_changed(client, monkeypatch):
    _session_id, _request_id, finding_id = await _seed()

    class _Response:
        status_code = 403
        content = b"blocked"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, *args, **kwargs):
            return _Response()

    import api.routes.smart_triage as triage

    monkeypatch.setattr(triage, "authorize", lambda *a, **k: _allow())
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _Client())

    async with client as c:
        response = await c.get(f"/api/triage/findings/{finding_id}/retest")

    body = response.json()
    # A different status can be a WAF or a rotated session: it is not proof the
    # bug is gone, so the finding is not silently marked fixed.
    assert body["result"] == "needs_review"
    assert body["triage_status"] == "needs_review"


@pytest.mark.asyncio
async def test_retest_refuses_a_target_that_is_no_longer_authorized(client, monkeypatch):
    _session_id, _request_id, finding_id = await _seed()

    import api.routes.smart_triage as triage

    async def _deny(*_args, **_kwargs):
        return (False, "roe", "outside the engagement window")

    monkeypatch.setattr(triage, "authorize", _deny)

    async with client as c:
        response = await c.get(f"/api/triage/findings/{finding_id}/retest")

    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"]


@pytest.mark.asyncio
async def test_retest_of_active_finding_without_request_id(client, monkeypatch):
    """An active scan on a custom URL has no captured request; retest must work anyway.

    The live review reproduced ``400 Associated request not found`` right after
    an active scan created a finding with ``request_id=null``.
    """
    from core.events.bus import EventBus
    from core.storage.crud.sessions import create_session
    from core.storage.finding_events import persist_results
    from modules.scanner.base_check import CheckResult

    async with AsyncSessionLocal() as db:
        session = await create_session(db, name=f"active-{uuid.uuid4().hex[:6]}")
        session_id = session.id

    result = CheckResult(
        triggered=True,
        severity="high",
        title="SQL Injection",
        description="id is injectable",
        evidence="Payload reflected",
        cwe="CWE-89",
        param="id",
    )
    await persist_results(
        EventBus(),
        [result],
        {
            "session_id": str(session_id),
            "method": "GET",
            "url": "https://target.test/item?id=1",
            "request_headers": {"Host": "target.test"},
            "request_body": None,
            "response_status": 200,
        },
        "active_sqli",
        source="active",
    )

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select

        finding = (
            await db.execute(
                select(Finding).where(Finding.session_id == session_id).limit(1)
            )
        ).scalar_one()
        assert finding.request_id is not None
        request = await db.get(Request, finding.request_id)
        assert request is not None
        assert request.url == "https://target.test/item?id=1"
        assert request.response_status == 200
        finding_id = finding.id

    class _Response:
        status_code = 200
        content = b"still vulnerable"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, *args, **kwargs):
            return _Response()

    import api.routes.smart_triage as triage

    monkeypatch.setattr(triage, "authorize", lambda *a, **k: _allow())
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _Client())

    async with client as c:
        response = await c.get(f"/api/triage/findings/{finding_id}/retest")

    assert response.status_code == 200, response.text
    assert response.json()["result"] == "confirmed"


async def _allow():
    return (True, "roe", "")


async def _seed_evidence_only(evidence: str | None) -> tuple[str, str]:
    """Session + finding with no Request row: the evidence is all there is."""
    async with AsyncSessionLocal() as db:
        from core.storage.crud.sessions import create_session

        session = await create_session(db, name=f"triage-evidence-{uuid.uuid4().hex[:6]}")
        finding = Finding(
            session_id=session.id,
            request_id=None,
            module="active_sqli",
            severity=SeverityEnum.HIGH,
            title="SQL Injection",
            description="id is injectable",
            evidence=evidence,
            cwe="CWE-89",
        )
        db.add(finding)
        await db.commit()
        return str(session.id), str(finding.id)


@pytest.mark.asyncio
async def test_retest_replays_a_finding_whose_request_row_is_gone(client, monkeypatch):
    """Old findings have no Request row; the stored curl evidence is replayable."""
    _session_id, finding_id = await _seed_evidence_only(
        "Boolean payload changed the response\n\nReproduce:\n"
        "curl -i -X GET 'https://target.test/item?id=1%27+OR+1%3D1--'\n\n"
        "# response: 200"
    )
    called: dict = {}

    class _Response:
        status_code = 200
        content = b"admin"

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, *args, **kwargs):
            called["method"] = args[0] if args else kwargs.get("method")
            called["url"] = args[1] if len(args) > 1 else kwargs.get("url")
            return _Response()

    import api.routes.smart_triage as triage

    monkeypatch.setattr(triage, "authorize", lambda *a, **k: _allow())
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: _Client())

    async with client as c:
        response = await c.get(f"/api/triage/findings/{finding_id}/retest")

    assert response.status_code == 200, response.text
    assert called["method"] == "get"
    assert called["url"] == "https://target.test/item?id=1%27+OR+1%3D1--"
    # The evidence carries no baseline status, so a re-send alone cannot confirm
    # anything: the operator decides.
    assert response.json()["result"] == "needs_review"


@pytest.mark.asyncio
async def test_retest_reports_not_retestable_instead_of_a_generic_400(client):
    _session_id, finding_id = await _seed_evidence_only(None)

    async with client as c:
        response = await c.get(f"/api/triage/findings/{finding_id}/retest")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["result"] == "not_retestable"
    assert body["triage_status"] == "open"
