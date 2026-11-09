"""Report generation over HTTP: formats, headers and honest PDF failure."""
import sys
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from main import app


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def session_id():
    return uuid.uuid4()


@pytest.mark.asyncio
@pytest.mark.parametrize("fmt,content_type", [
    ("html", "text/html"),
    ("json", "application/json"),
    ("md", "text/markdown"),
])
async def test_report_formats(client, session_id, fmt, content_type):
    async with client as c:
        response = await c.post(
            "/api/reports/generate",
            params={"session_id": str(session_id), "format": fmt},
        )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith(content_type)
    disposition = response.headers.get("content-disposition", "")
    assert disposition.startswith("attachment;")
    assert f"{str(session_id)[:8]}.{fmt}" in disposition


@pytest.mark.asyncio
async def test_report_requires_session(client):
    async with client as c:
        response = await c.post("/api/reports/generate")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_pdf_without_weasyprint_is_a_clear_400(client, session_id, monkeypatch):
    monkeypatch.setitem(sys.modules, "weasyprint", None)
    async with client as c:
        response = await c.post(
            "/api/reports/generate",
            params={"session_id": str(session_id), "format": "pdf"},
        )
    assert response.status_code == 400, response.text
    assert "weasyprint" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_report_rejects_unknown_format(client, session_id):
    async with client as c:
        response = await c.post(
            "/api/reports/generate",
            params={"session_id": str(session_id), "format": "docx"},
        )
    assert response.status_code == 422
