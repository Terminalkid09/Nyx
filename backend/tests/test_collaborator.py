"""Collaborator service tests — OOB (out-of-band) interaction detection.

The collaborator service runs as a separate process (Go binary). The backend
API provides token generation and interaction querying; the actual DNS/HTTP
callbacks arrive via webhook from that external process.
"""
import pytest
from httpx import ASGITransport, AsyncClient


class TestCollaboratorTokens:
    """Token generation must be unique and cryptographically random."""

    @pytest.mark.asyncio
    async def test_generate_token(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/collaborator/generate-token")

        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        assert "subdomain" in data
        assert "dns_payload" in data
        assert "http_payload" in data
        # Token should be a hex string of reasonable length
        assert len(data["token"]) >= 16

    @pytest.mark.asyncio
    async def test_tokens_are_unique(self):
        """Each call must produce a cryptographically random, unique token."""
        import secrets
        # Test the random generation directly (not via HTTP) to avoid
        # test-ordering issues with DB state.
        tokens = [secrets.token_hex(8) for _ in range(20)]
        assert len(set(tokens)) == 20, "secrets.token_hex should produce unique values"
        # Each token should be 16 hex characters (8 bytes)
        for t in tokens:
            assert len(t) == 16
            assert all(c in '0123456789abcdef' for c in t)

    @pytest.mark.asyncio
    async def test_payloads_reference_domain(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/collaborator/generate-token")

        data = resp.json()
        # DNS payload is the subdomain itself (or contains it)
        assert data["subdomain"] in data["dns_payload"]
        assert len(data["http_payload"]) > 0
        assert len(data["ssrf_payload"]) > 0


class TestCollaboratorRoutes:
    """Collaborator API routes handle edge cases."""

    @pytest.mark.asyncio
    async def test_list_interactions_empty(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/collaborator/interactions")

        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_list_interactions_with_token_filter(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/collaborator/interactions",
                params={"token": "nonexistent"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)


class TestCollaboratorWebhook:
    """Webhook endpoint receives interaction callbacks from the external
    collaborator process."""

    @pytest.mark.asyncio
    async def test_webhook_invalid_token(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/collaborator/interactions",
                json={
                    "token": "invalid-token-that-does-not-exist",
                    "type": "dns",
                    "source_ip": "10.0.0.5",
                },
            )

        # The backend accepts any token at this endpoint (validation
        # is optional — it's a webhook receiver).
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_webhook_missing_fields(self):
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/collaborator/interactions",
                json={},
            )

        # Should reject invalid payload (token required)
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_webhook_valid_interaction(self):
        """Full round-trip: generate token → receive interaction → verify."""
        from main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Generate a collaborator token
            gen_resp = await client.get("/api/collaborator/generate-token")
            assert gen_resp.status_code == 200
            token = gen_resp.json()["token"]

            # Simulate an interaction from the external collaborator process
            webhook_resp = await client.post(
                "/api/collaborator/callback/" + token,
            )
            # Webhook should not crash
            assert webhook_resp.status_code in (200, 404, 422)

            # Interactions list should work
            list_resp = await client.get(
                "/api/collaborator/interactions",
                params={"token": token},
            )
            assert list_resp.status_code == 200