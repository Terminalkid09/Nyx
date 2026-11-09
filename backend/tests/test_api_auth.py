import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def transport():
    from main import app
    return ASGITransport(app=app)


@pytest.mark.asyncio
async def test_health_no_key(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/health")
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_localhost_bypasses_auth(transport):
    """ASGITransport client is 127.0.0.1, so API key is NOT required."""
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/sessions")
        # localhost bypasses key check, so 200/404 expected, NOT 401
        assert r.status_code != 401


@pytest.mark.asyncio
async def test_auth_key_endpoint(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/auth/key")
        assert r.status_code == 200
        assert len(r.text) > 16


@pytest.mark.asyncio
async def test_auth_key_requires_session_token_in_token_mode(transport, require_token):
    """The key must not be readable by an unauthenticated local process."""
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/auth/key")
    assert r.status_code == 403
    assert "X-Nyx-Token" in r.json()["detail"]


@pytest.mark.asyncio
async def test_auth_key_with_session_token_in_token_mode(transport, require_token):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get(
            "/api/auth/key",
            headers={"X-Nyx-Token": require_token.SESSION_TOKEN},
        )
    assert r.status_code == 200
    assert r.text == require_token.API_KEY


@pytest.mark.asyncio
async def test_ws_path_no_auth(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/ws/test")
        assert r.status_code != 401


@pytest.mark.asyncio
async def test_cert_path_no_auth(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/ca-certificate")
        assert r.status_code != 401


# ── SEC-03b: loopback callers must present the per-boot token ───────────────


@pytest.fixture
def require_token(monkeypatch):
    """Turn the desktop-mode token gate on for the duration of a test."""
    from core import api_auth

    monkeypatch.setattr(api_auth.settings, "API_REQUIRE_SESSION_TOKEN", True)
    return api_auth


@pytest.mark.asyncio
async def test_loopback_rejected_without_session_token(transport, require_token):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/sessions")
    assert r.status_code == 403
    assert "X-Nyx-Token" in r.json()["detail"]


@pytest.mark.asyncio
async def test_loopback_rejected_with_wrong_session_token(transport, require_token):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/sessions", headers={"X-Nyx-Token": "not-the-token"})
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_loopback_accepted_with_session_token(transport, require_token):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/sessions", headers={"X-Nyx-Token": require_token.SESSION_TOKEN})
    assert r.status_code != 403


@pytest.mark.asyncio
async def test_token_gate_is_off_by_default(transport):
    """Dev mode and the CLI keep working: no header, no 403."""
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/sessions")
    assert r.status_code != 403


def test_session_token_is_persisted_for_the_shell(require_token):
    """The Electron main process can only read the token off disk."""
    token = require_token.SESSION_TOKEN
    assert len(token) >= 32
    assert require_token.SESSION_TOKEN_FILE.read_text(encoding="utf-8").strip() == token
