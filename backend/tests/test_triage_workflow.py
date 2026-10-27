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


async def _allow():
    return (True, "roe", "")
