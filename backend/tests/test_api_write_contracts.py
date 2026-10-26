"""Write endpoints must validate input instead of raising 500."""
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from main import app


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_custom_check_serialises_datetime(client):
    async with client as c:
        response = await c.post("/api/scanner/custom/", json={
            "name": "sweep-check",
            "match_pattern": "root:",
        })
    assert response.status_code == 201, response.text
    assert isinstance(response.json()["created_at"], str)


@pytest.mark.asyncio
async def test_comparer_item_serialises_datetime(client):
    from core.storage.traffic import DEFAULT_SESSION_ID

    async with client as c:
        response = await c.post("/api/comparer/items", json={
            "session_id": str(DEFAULT_SESSION_ID),
            "left_content": "a",
            "right_content": "b",
        })
    assert response.status_code == 201, response.text
    assert isinstance(response.json()["created_at"], str)


@pytest.mark.asyncio
async def test_html_encode_invalid_mode_is_400(client):
    async with client as c:
        response = await c.post("/api/decoder/html-encode", json={
            "input": "<a>", "mode": "bogus",
        })
    assert response.status_code == 400
    assert "mode" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_record_rejects_invalid_session(client):
    async with client as c:
        response = await c.post("/api/auth/login/record", json={
            "session_id": "not-a-uuid",
        })
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_project_import_without_session_data(client):
    async with client as c:
        response = await c.post("/api/projects/import", json={
            "project": {"name": "imported"},
        })
    assert response.status_code == 200, response.text
    assert response.json()["session_id"]
