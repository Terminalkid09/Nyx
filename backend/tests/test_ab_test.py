"""Multi-identity replay: classifier, anonymous leg and API contract."""
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from main import app
from modules.ab_test.service import (
    Identity,
    Sample,
    classify,
    normalise,
    run_comparison,
)


def sample(label="a", status=200, body="", **kwargs):
    return Sample(label=label, status=status, body=body, length=len(body), **kwargs)


def test_same_body_for_both_identities_is_suspected_idor():
    result = classify(
        sample("alice", body='{"items": [1, 2, 3]}'),
        sample("bob", body='{"items": [1, 2, 3]}'),
    )
    assert result.verdict == "suspected_idor"
    assert result.severity == "high"
    assert "same_body" in result.signals
    assert result.similarity >= 0.95


def test_different_bodies_are_reported_as_isolated():
    result = classify(
        sample("alice", body="alice's private invoices, tenant one"),
        sample("bob", body="<html>completely different page for another customer</html>"),
    )
    assert result.verdict == "isolated"
    assert "different_body" in result.signals
    assert result.similarity < 0.70


def test_one_sided_denial_is_isolated():
    result = classify(sample("alice", body="secret"), sample("bob", status=403, body="forbidden"))
    assert result.verdict == "isolated"
    assert "second_identity_denied" in result.signals


def test_reversed_access_is_flagged_for_review():
    result = classify(sample("alice", status=401, body=""), sample("bob", body="secret"))
    assert result.verdict == "review"
    assert "first_identity_denied" in result.signals


def test_nobody_has_access_is_inconclusive():
    result = classify(sample("alice", status=401), sample("bob", status=403))
    assert result.verdict == "inconclusive"
    assert "no_identity_has_access" in result.signals


def test_failed_request_is_inconclusive():
    result = classify(sample("alice", error="connect timeout"), sample("bob", body="x"))
    assert result.verdict == "inconclusive"
    assert result.signals == ["request_failed"]


def test_anonymous_same_body_outranks_idor():
    result = classify(
        sample("alice", body="customer list"),
        sample("bob", body="customer list"),
        sample("anonymous", body="customer list"),
    )
    assert result.verdict == "unauthenticated_access"
    assert "anonymous_sees_the_same_body" in result.signals


def test_normalise_ignores_rotated_tokens():
    first = '{"csrf": "8f14e45fceea167a5a36dedd4bea2543", "when": "20261026120000", "ok": true}'
    second = '{"csrf": "c9f0f895fb98ab9159f51fd0297e236d", "when": "20261026120515", "ok": true}'
    assert normalise(first) == normalise(second)

    result = classify(sample("alice", body=first), sample("bob", body=second))
    assert result.verdict == "suspected_idor"


def _transport(responses):
    """MockTransport that answers by Cookie header."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        cookie = request.headers.get("cookie", "")
        for marker, (status, body) in responses.items():
            if marker in cookie:
                return httpx.Response(status, text=body)
        return httpx.Response(401, text="unauthorized")

    return httpx.MockTransport(handler), seen


@pytest.mark.asyncio
async def test_run_comparison_sends_one_request_per_identity():
    transport, seen = _transport(
        {
            "session=alice": (200, '{"tenant": "alice-only"}'),
            "session=bob": (200, '<html>the other customer dashboard</html>'),
        }
    )
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
        result = await run_comparison(
            request={"method": "GET", "url": "https://target.test/api/me", "headers": {}, "body": None},
            identity_a=Identity("alice", {"Cookie": "session=alice"}),
            identity_b=Identity("bob", {"Cookie": "session=bob"}),
            client=client,
        )

    assert result.verdict == "isolated"
    assert len(seen) == 3
    assert [r.headers.get("cookie") for r in seen] == [
        "session=alice",
        "session=bob",
        None,
    ]


@pytest.mark.asyncio
async def test_anonymous_leg_strips_identity_headers():
    transport, seen = _transport(
        {
            "session=alice": (200, "public-ish page"),
            "session=bob": (200, "another page entirely, quite different"),
        }
    )
    async with httpx.AsyncClient(transport=transport, follow_redirects=False) as client:
        result = await run_comparison(
            request={
                "method": "GET",
                "url": "https://target.test/api/page",
                "headers": {"Cookie": "session=alice", "Accept": "text/html"},
                "body": None,
            },
            identity_a=Identity("alice", {"Cookie": "session=alice"}),
            identity_b=Identity("bob", {"Cookie": "session=bob"}),
            client=client,
        )

    anonymous_request = seen[2]
    assert "cookie" not in anonymous_request.headers
    # Non-credential headers the operator supplied are still sent.
    assert anonymous_request.headers["accept"] == "text/html"
    assert result.samples[-1].label == "anonymous"


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_route_returns_the_diff(client, monkeypatch):
    from modules.ab_test.service import DiffResult

    async def fake_run_comparison(**kwargs):
        assert kwargs["identity_a"].name == "alice"
        return DiffResult(
            verdict="suspected_idor",
            severity="high",
            confidence=1.0,
            similarity=1.0,
            signals=["both_identities_succeeded", "same_body"],
            samples=[sample("alice", body="x"), sample("bob", body="x")],
        )

    monkeypatch.setattr("api.routes.ab_test.run_comparison", fake_run_comparison)

    async with client as c:
        response = await c.post(
            "/api/ab-test/run",
            json={
                "url": "https://target.test/api/items/1",
                "identity_a": {"name": "alice", "headers": {"Cookie": "session=alice"}},
                "identity_b": {"name": "bob", "headers": {"Cookie": "session=bob"}},
            },
        )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["verdict"] == "suspected_idor"
    assert payload["severity"] == "high"
    assert [s["label"] for s in payload["samples"]] == ["alice", "bob"]


@pytest.mark.asyncio
async def test_route_rejects_non_http_urls(client):
    async with client as c:
        response = await c.post(
            "/api/ab-test/run",
            json={
                "url": "file:///etc/passwd",
                "identity_a": {"name": "a"},
                "identity_b": {"name": "b"},
            },
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_route_rejects_a_bad_session_id(client):
    async with client as c:
        response = await c.post(
            "/api/ab-test/run",
            json={
                "url": "https://target.test/",
                "session_id": "not-a-uuid",
                "identity_a": {"name": "a"},
                "identity_b": {"name": "b"},
            },
        )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_route_honours_the_authorization_gate(client, monkeypatch):
    monkeypatch.setattr(
        "api.routes.ab_test.authorize",
        AsyncMock(return_value=(False, "roe", "outside the engagement window")),
    )
    async with client as c:
        response = await c.post(
            "/api/ab-test/run",
            json={
                "url": "https://target.test/",
                "identity_a": {"name": "a"},
                "identity_b": {"name": "b"},
            },
        )
    assert response.status_code == 403
    assert "not authorized" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_route_requires_identity_names(client):
    async with client as c:
        response = await c.post(
            "/api/ab-test/run",
            json={
                "url": "https://target.test/",
                "identity_a": {"name": ""},
                "identity_b": {"name": "b"},
            },
        )
    assert response.status_code == 422
