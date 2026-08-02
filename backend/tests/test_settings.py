import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from api.routes.settings import router as settings_router


@pytest.fixture
def app():
    app = FastAPI()
    app.include_router(settings_router)
    return app


@pytest.mark.asyncio
async def test_get_proxy_settings_returns_defaults(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/settings/proxy")
    assert resp.status_code == 200
    body = resp.json()
    assert "host" in body
    assert "port" in body
    assert "mode" in body
    assert isinstance(body["port"], int)


@pytest.mark.asyncio
async def test_get_proxy_settings_has_expected_fields(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/settings/proxy")
    body = resp.json()
    assert set(body.keys()) == {"host", "port", "mode"}


@pytest.mark.asyncio
async def test_update_proxy_settings_returns_new_values(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.put("/api/settings/proxy", json={
            "host": "127.0.0.1",
            "port": 9090,
            "mode": "regular",
        })
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"host": "127.0.0.1", "port": 9090, "mode": "regular"}


@pytest.mark.asyncio
async def test_update_proxy_settings_rejects_invalid_body(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.put("/api/settings/proxy", json={
            "host": "0.0.0.0",
            "port": "not-a-number",
            "mode": "regular",
        })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_all_settings_returns_api_info(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/settings/")
    assert resp.status_code == 200
    body = resp.json()
    assert "proxy" in body
    assert "api_host" in body
    assert "api_port" in body
    assert isinstance(body["api_port"], int)
    assert isinstance(body["api_host"], str)
    assert set(body["proxy"].keys()) == {"host", "port", "mode"}


@pytest.mark.asyncio
async def test_get_all_settings_proxy_matches_get_proxy(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        all_resp = await client.get("/api/settings/")
        proxy_resp = await client.get("/api/settings/proxy")
    assert all_resp.status_code == 200
    assert proxy_resp.status_code == 200
    assert all_resp.json()["proxy"] == proxy_resp.json()


@pytest.mark.asyncio
async def test_update_then_get_returns_updated_value(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        put_resp = await client.put("/api/settings/proxy", json={
            "host": "0.0.0.0",
            "port": 8080,
            "mode": "transparent",
        })
        get_resp = await client.get("/api/settings/proxy")
    assert put_resp.status_code == 200
    assert get_resp.status_code == 200
    assert get_resp.json() == {"host": "0.0.0.0", "port": 8080, "mode": "transparent"}
