"""F-04: PoC verification."""
import pytest
from httpx import ASGITransport, AsyncClient

from modules.auto_exploit.verifier import Sample, classify
from api.routes.verifier import inject_query


def sample(status=200, body="hello world", time_ms=50):
    return Sample(status=status, body=body, time_ms=time_ms)


class TestClassify:
    def test_identical_is_unverified(self):
        assert classify(sample(), sample()).verdict == "unverified"

    def test_status_change_is_confirmed(self):
        verdict = classify(sample(), sample(status=500))
        assert verdict.verdict == "confirmed"
        assert "status_changed" in verdict.signals

    def test_large_body_change_is_confirmed(self):
        verdict = classify(sample(body="a" * 500), sample(body="b" * 500))
        assert verdict.verdict == "confirmed"
        assert "body_changed" in verdict.signals

    def test_small_body_change_is_probable(self):
        verdict = classify(
            sample(body="a" * 1000),
            sample(body="a" * 900 + "b" * 100),
        )
        assert verdict.verdict == "probable"

    def test_time_delta_is_confirmed(self):
        verdict = classify(sample(), sample(time_ms=3500))
        assert verdict.verdict == "confirmed"
        assert "time_delta" in verdict.signals

    def test_verdict_serialises(self):
        payload = classify(sample(), sample(status=403)).to_dict()
        assert payload["verdict"] == "confirmed"
        assert isinstance(payload["similarity"], float)


def test_inject_query_replaces_param():
    url = inject_query("https://example.com/?id=1&x=2", "id", "1' OR 1=1--")
    assert "x=2" in url
    assert "id=1%27+OR+1%3D1--" in url


@pytest.fixture
def transport():
    from main import app
    return ASGITransport(app=app)


@pytest.mark.asyncio
async def test_verify_endpoint_returns_verdict(monkeypatch, transport):
    async def allow(session_id, url, **kwargs):
        assert kwargs.get("require_session") is True
        return True, None, None

    class FakeVerdict:
        def to_dict(self):
            return {"verdict": "confirmed", "signals": ["status_changed"]}

    async def fake_run(baseline, injected, client=None):
        assert injected["url"] != baseline["url"]
        return FakeVerdict()

    monkeypatch.setattr("api.routes.verifier.authorize", allow)
    monkeypatch.setattr("api.routes.verifier.run_verification", fake_run)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/auto-exploit/verify",
            json={
                "url": "https://example.com/?id=1",
                "param": "id",
                "payload": "1' OR 1=1--",
                "session_id": "11111111-1111-1111-1111-111111111111",
            },
        )
    assert response.status_code == 200
    assert response.json()["verdict"] == "confirmed"


@pytest.mark.asyncio
async def test_verify_endpoint_blocks_out_of_scope(monkeypatch, transport):
    async def deny(session_id, url, **kwargs):
        return False, "roe", "no_authorization_profile"

    monkeypatch.setattr("api.routes.verifier.authorize", deny)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/auto-exploit/verify",
            json={
                "url": "https://example.com/",
                "session_id": "11111111-1111-1111-1111-111111111111",
            },
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_verify_endpoint_requires_a_session(monkeypatch, transport):
    async def should_not_run(*args, **kwargs):
        raise AssertionError("verification ran without a session")

    monkeypatch.setattr("api.routes.verifier.run_verification", should_not_run)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/auto-exploit/verify", json={"url": "https://example.com/"}
        )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_verify_endpoint_checks_injected_url(monkeypatch, transport):
    async def conditional(session_id, url, **kwargs):
        if url == "https://example.com/?id=1":
            return True, None, None
        return False, "roe", "excluded"

    async def should_not_run(*args, **kwargs):
        raise AssertionError("verification ran despite a blocked injected URL")

    monkeypatch.setattr("api.routes.verifier.authorize", conditional)
    monkeypatch.setattr("api.routes.verifier.run_verification", should_not_run)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/auto-exploit/verify",
            json={
                "url": "https://example.com/?id=1",
                "param": "id",
                "payload": "1' OR 1=1--",
                "session_id": "11111111-1111-1111-1111-111111111111",
            },
        )
    assert response.status_code == 403
