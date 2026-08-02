import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI


@pytest.fixture
def app():
    from api.routes.interceptor import router
    app = FastAPI()
    app.include_router(router)
    return app


class TestInterceptorStatusEndpoint:
    @pytest.mark.asyncio
    async def test_get_interceptor_status_without_engine_returns_503(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/interceptor/status")
        assert resp.status_code == 503


class TestInterceptorPausedEndpoint:
    @pytest.mark.asyncio
    async def test_get_paused_without_engine_returns_503(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/interceptor/paused")
        assert resp.status_code == 503


class TestInterceptorForwardEndpoint:
    @pytest.mark.asyncio
    async def test_forward_without_engine_returns_503(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/interceptor/forward/test-id")
        assert resp.status_code == 503


class TestInterceptorDropEndpoint:
    @pytest.mark.asyncio
    async def test_drop_without_engine_returns_503(self, app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/interceptor/drop/test-id")
        assert resp.status_code == 503



