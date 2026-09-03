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
async def test_ws_path_no_auth(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/ws/test")
        assert r.status_code != 401


@pytest.mark.asyncio
async def test_cert_path_no_auth(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        r = await c.get("/api/ca-certificate")
        assert r.status_code != 401
