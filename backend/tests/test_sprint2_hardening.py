"""Unit coverage for the small hardening fixes in v1.1 Sprint 2."""
import asyncio
from pathlib import Path

import pytest

from core import secrets_store
from core.config import _default_database_url, settings
from core.events.bus import EventBus
from core.metrics import registry
from core.proxy.addons import logger as proxy_logger
from core.storage.encrypted import pragma_key_literal
from modules.fuzzer.service import MAX_RESULT_FIELD, truncate_result


class TestDatabasePath:
    def test_default_url_is_absolute(self, monkeypatch):
        monkeypatch.delenv("NYX_HOME", raising=False)
        url = _default_database_url()
        assert url.startswith("sqlite+aiosqlite:///")
        path = url.replace("sqlite+aiosqlite:///", "")
        assert Path(path).is_absolute()

    def test_nyx_home_wins(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NYX_HOME", str(tmp_path))
        url = _default_database_url()
        assert url == f"sqlite+aiosqlite:///{(tmp_path / 'nyx.db').as_posix()}"


class TestPragmaKey:
    def test_accepts_normal_key(self):
        assert pragma_key_literal("abc123") == "'abc123'"

    @pytest.mark.parametrize("key", ["a'b", "a\x00b", ""])
    def test_rejects_injection(self, key):
        with pytest.raises(ValueError):
            pragma_key_literal(key)


class TestFuzzTruncation:
    def test_truncates_request_and_response(self):
        result = {"request": "x" * (MAX_RESULT_FIELD + 10), "response": "y" * 10}
        out = truncate_result(result)
        assert len(out["request"]) == MAX_RESULT_FIELD
        assert out["truncated"] is True
        assert out["response"] == "y" * 10

    def test_short_result_untouched(self):
        result = {"request": "short", "response": None}
        assert truncate_result(result) == {"request": "short", "response": None}


class TestNoiseDomains:
    def test_override_is_comma_separated(self, monkeypatch):
        monkeypatch.setattr(settings, "PROXY_NOISE_DOMAINS", "a.example, B.example")
        assert proxy_logger.noise_domains() == {"a.example", "b.example"}

    def test_empty_uses_builtin_defaults(self, monkeypatch):
        monkeypatch.setattr(settings, "PROXY_NOISE_DOMAINS", "")
        assert "ctldl.windowsupdate.com" in proxy_logger.noise_domains()


class TestSecretsPermissions:
    def test_windows_uses_icacls(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(secrets_store.os, "name", "nt")
        monkeypatch.setenv("USERNAME", "tester")
        monkeypatch.setattr(
            secrets_store.subprocess, "run",
            lambda *a, **kw: calls.append((a, kw)),
        )
        secrets_store.restrict_to_owner(tmp_path / "nyx.secret")
        assert calls
        assert calls[0][0][0][0] == "icacls"
        assert calls[0][1]["shell"] is False

    def test_posix_uses_chmod(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(secrets_store.os, "name", "posix")
        monkeypatch.setattr(
            secrets_store.os, "chmod",
            lambda path, mode: calls.append((path, mode)),
        )
        target = tmp_path / "nyx.secret"
        secrets_store.restrict_to_owner(target)
        assert calls == [(str(target), 0o600)]


@pytest.mark.asyncio
async def test_event_bus_drop_is_counted(monkeypatch):
    bus = EventBus()
    before = registry.counter("events_dropped_total")

    async def handler(event):
        return None

    bus.subscribe("test.drop", handler)

    async def timeout(*args, **kwargs):
        raise asyncio.TimeoutError

    monkeypatch.setattr(bus._semaphore, "acquire", timeout)
    await bus.publish({"type": "test.drop"})

    assert registry.counter("events_dropped_total") == before + 1
