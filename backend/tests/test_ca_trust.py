"""CA trust on the operator machine: report the state, verify the removal.

Installing the Nyx CA is meant for the target device; on the operator PC it is
optional. What must never happen is a removal that looks successful while the
certificate is still trusted, so ``remove_ca_verified`` re-reads the stores and
the API exposes that state.
"""
import subprocess

import pytest
from httpx import ASGITransport, AsyncClient

from main import app
import core.proxy.engine as engine


def _completed(stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["powershell"], returncode=0, stdout=stdout, stderr="")


@pytest.mark.asyncio
async def test_remove_reports_store_that_still_holds_the_ca(monkeypatch):
    monkeypatch.setattr(engine.platform, "system", lambda: "Windows")
    monkeypatch.setattr(engine, "_run_powershell", lambda *a, **k: _completed())
    counts = iter([{"CurrentUser": 1, "LocalMachine": 1},
                   {"CurrentUser": 0, "LocalMachine": 1}])
    monkeypatch.setattr(engine, "_windows_ca_counts", lambda: next(counts))

    result = engine.remove_ca_verified()

    assert result["removed"] is False
    assert result["still_present"] == ["LocalMachine"]
    assert result["stores"]["LocalMachine"] == {"before": 1, "after": 1}
    assert "Administrator" in result["message"]


@pytest.mark.asyncio
async def test_remove_verified_when_both_stores_are_empty(monkeypatch):
    monkeypatch.setattr(engine.platform, "system", lambda: "Windows")
    monkeypatch.setattr(engine, "_run_powershell", lambda *a, **k: _completed())
    counts = iter([{"CurrentUser": 1, "LocalMachine": 1},
                   {"CurrentUser": 0, "LocalMachine": 0}])
    monkeypatch.setattr(engine, "_windows_ca_counts", lambda: next(counts))

    result = engine.remove_ca_verified()

    assert result["removed"] is True
    assert result["still_present"] == []
    assert "verified" in result["message"].lower()


def test_remove_is_never_verified_when_stores_cannot_be_read(monkeypatch):
    monkeypatch.setattr(engine.platform, "system", lambda: "Windows")
    monkeypatch.setattr(engine, "_run_powershell", lambda *a, **k: _completed())
    monkeypatch.setattr(engine, "_windows_ca_counts", lambda: {})

    result = engine.remove_ca_verified()

    assert result["removed"] is False
    assert "not " in result["message"].lower() or "could not" in result["message"].lower()


def test_trust_state_reports_unknown_instead_of_false(monkeypatch):
    monkeypatch.setattr(engine.platform, "system", lambda: "Windows")
    monkeypatch.setattr(engine, "_windows_ca_counts", lambda: {})

    state = engine.ca_trust_state()

    assert state["trusted"] is None
    assert state["inconclusive"] is True


def test_trust_state_reports_per_store_counts(monkeypatch):
    monkeypatch.setattr(engine.platform, "system", lambda: "Windows")
    monkeypatch.setattr(engine, "_windows_ca_counts",
                        lambda: {"CurrentUser": 0, "LocalMachine": 1})

    state = engine.ca_trust_state()

    assert state["trusted"] is True
    assert state["stores"] == {"CurrentUser": 0, "LocalMachine": 1}


@pytest.mark.asyncio
async def test_ca_status_endpoint(monkeypatch):
    monkeypatch.setattr(engine, "ca_trust_state", lambda: {
        "platform": "windows",
        "trusted": False,
        "inconclusive": False,
        "stores": {"CurrentUser": 0, "LocalMachine": 0},
        "detail": "test",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/ca/status")
    assert response.status_code == 200
    body = response.json()
    assert body["trusted"] is False
    assert body["stores"] == {"CurrentUser": 0, "LocalMachine": 0}
    assert "certificate" in body


@pytest.mark.asyncio
async def test_remove_endpoint_exposes_the_verification(monkeypatch):
    monkeypatch.setattr(engine, "remove_ca_verified", lambda: {
        "platform": "windows",
        "removed": False,
        "still_present": ["LocalMachine"],
        "stores": {"CurrentUser": {"before": 0, "after": 0},
                   "LocalMachine": {"before": 1, "after": 1}},
        "message": "CA still present in LocalMachine.",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/ca/remove")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert body["removed"] is False
    assert body["still_present"] == ["LocalMachine"]
