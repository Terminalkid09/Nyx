"""PUT /api/settings/proxy must validate input and never leave the proxy down.

The endpoint stops and restarts the proxy engine (system proxy, IP forwarding,
WinDivert). A sweep that called it with an invalid mode killed the backend's
listener; a failed restart used to leave capture dead for the rest of the
session with no rollback.
"""
import pytest
from httpx import ASGITransport, AsyncClient

from main import app


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class _FakeEngine:
    def __init__(self, fail_on_modes=()):
        self.host = "0.0.0.0"
        self.port = 8080
        self.mode = "regular"
        self.fastapi_loop = None
        self.fail_on_modes = set(fail_on_modes)
        self.starts = 0

    def stop(self):
        return None

    def start(self, _loop):
        if self.mode in self.fail_on_modes:
            raise RuntimeError(f"cannot start in {self.mode} mode")
        self.starts += 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["socks5", "", "TRANSPARENT "])
async def test_invalid_mode_is_rejected(client, mode):
    async with client as c:
        response = await c.put("/api/settings/proxy", json={"host": "0.0.0.0", "port": 8080, "mode": mode})
    # "TRANSPARENT " normalises to a valid value; the others are rejected.
    if mode.strip().lower() in {"regular", "transparent"}:
        assert response.status_code == 200, response.text
    else:
        assert response.status_code == 422, response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("port", [0, 70000, -1])
async def test_invalid_port_is_rejected(client, port):
    async with client as c:
        response = await c.put("/api/settings/proxy", json={"host": "0.0.0.0", "port": port, "mode": "regular"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_failed_restart_rolls_back(client):
    engine = _FakeEngine(fail_on_modes={"transparent"})
    app.state.proxy_engine = engine
    try:
        async with client as c:
            response = await c.put(
                "/api/settings/proxy",
                json={"host": "0.0.0.0", "port": 8080, "mode": "transparent"},
            )
        assert response.status_code == 500
        assert "restored" in response.json()["detail"].lower()
        # The engine must be back on the last working configuration.
        assert engine.mode == "regular"
        assert engine.starts == 1
    finally:
        del app.state.proxy_engine
