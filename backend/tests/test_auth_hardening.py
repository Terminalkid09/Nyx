"""SEC-03: Host allowlist and cross-site rejection (DNS rebinding guard)."""
import pytest
from httpx import ASGITransport, AsyncClient

from core.api_auth import _hostname, is_allowed_host, is_trusted_proxy


class TestHostParsing:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("localhost:8000", "localhost"),
            ("127.0.0.1:8000", "127.0.0.1"),
            ("[::1]:8000", "::1"),
            ("::1", "::1"),
            ("TEST:80", "test"),
            ("", ""),
        ],
    )
    def test_hostname(self, header, expected):
        assert _hostname(header) == expected

    @pytest.mark.parametrize(
        "header", ["localhost:8000", "127.0.0.1:8000", "[::1]:5173", "test"]
    )
    def test_allows_loopback_and_test_hosts(self, header):
        assert is_allowed_host(header) is True

    @pytest.mark.parametrize(
        "header", ["evil.example", "evil.example:8000", "127.0.0.1.evil.example"]
    )
    def test_rejects_foreign_hosts(self, header):
        assert is_allowed_host(header) is False

    def test_trusted_proxy_checks_cidr(self):
        assert is_trusted_proxy("not-an-ip") is False
        assert is_trusted_proxy("203.0.113.10") is False


@pytest.fixture
def transport():
    from main import app
    return ASGITransport(app=app)


@pytest.mark.asyncio
async def test_foreign_host_header_rejected(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/sessions", headers={"host": "evil.example"})
    assert response.status_code == 403
    assert "Host" in response.text


@pytest.mark.asyncio
async def test_cross_site_fetch_rejected(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/sessions", headers={"sec-fetch-site": "cross-site"}
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_same_origin_still_works(transport):
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/sessions", headers={"sec-fetch-site": "same-origin"}
        )
    assert response.status_code != 403
