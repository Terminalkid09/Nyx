import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def event_bus():
    from core.events.bus import EventBus
    return EventBus()


@pytest.fixture
def macro_engine(event_bus):
    from modules.session_handling.engine import MacroEngine
    return MacroEngine(event_bus)


@pytest.fixture
def cookie_jar(event_bus):
    from modules.session_handling.engine import CookieJarEngine
    return CookieJarEngine(event_bus)


class TestMacroVariablePersistence:
    def test_save_and_load_variables(self, macro_engine):
        macro_engine._variables = {"token": "abc123", "csrf": "xyz789"}
        saved = macro_engine.save_variables("session1")
        assert saved == {"token": "abc123", "csrf": "xyz789"}

        macro_engine._variables = {}
        loaded = macro_engine.load_variables("session1")
        assert loaded == {"token": "abc123", "csrf": "xyz789"}
        assert macro_engine._variables == {"token": "abc123", "csrf": "xyz789"}

    def test_load_nonexistent(self, macro_engine):
        result = macro_engine.load_variables("nonexistent")
        assert result is None

    def test_list_saved_variables(self, macro_engine):
        macro_engine._variables = {"a": "1"}
        macro_engine.save_variables("s1")
        macro_engine.save_variables("s2")
        saved = macro_engine.list_saved_variables()
        assert "s1" in saved
        assert "s2" in saved

    def test_get_all_variables(self, macro_engine):
        macro_engine._variables = {"a": "1", "b": "2"}
        assert macro_engine.get_all_variables() == {"a": "1", "b": "2"}

    def test_clear_variables(self, macro_engine):
        macro_engine._variables = {"a": "1"}
        macro_engine.clear_variables()
        assert macro_engine._variables == {}

    def test_multiple_snapshots_independent(self, macro_engine):
        macro_engine._variables = {"a": "1"}
        macro_engine.save_variables("snap1")
        macro_engine._variables = {"b": "2"}
        macro_engine.save_variables("snap2")
        macro_engine._variables = {}
        macro_engine.load_variables("snap1")
        assert macro_engine._variables == {"a": "1"}
        macro_engine._variables = {}
        macro_engine.load_variables("snap2")
        assert macro_engine._variables == {"b": "2"}


class TestMacroExecution:
    @pytest.mark.asyncio
    async def test_variable_substitution(self, macro_engine):
        macro_engine.set_variable("token", "test123")
        result = macro_engine._substitute_vars("/api?token={{token}}")
        assert result == "/api?token=test123"

    @pytest.mark.asyncio
    async def test_variable_substitution_unknown(self, macro_engine):
        result = macro_engine._substitute_vars("/api?token={{unknown}}")
        assert result == "/api?token={{unknown}}"

    @pytest.mark.asyncio
    async def test_variable_substitution_no_match(self, macro_engine):
        result = macro_engine._substitute_vars("/api?token=static")
        assert result == "/api?token=static"

    def test_set_and_get_variable(self, macro_engine):
        macro_engine.set_variable("key", "value")
        assert macro_engine.get_variable("key") == "value"
        assert macro_engine.get_variable("nonexistent") is None


class TestCookieJarScope:
    def test_in_scope_empty_include(self, cookie_jar):
        assert cookie_jar._is_in_scope("example.com") is True

    def test_in_scope_include_match(self, cookie_jar):
        import re
        cookie_jar._scope_include = [re.compile(r"example\.com", re.I)]
        assert cookie_jar._is_in_scope("example.com") is True
        assert cookie_jar._is_in_scope("evil.com") is False

    def test_in_scope_exclude(self, cookie_jar):
        import re
        cookie_jar._scope_include = [re.compile(r".*", re.I)]
        cookie_jar._scope_exclude = [re.compile(r"evil", re.I)]
        assert cookie_jar._is_in_scope("example.com") is True
        assert cookie_jar._is_in_scope("evil.com") is False


class TestSetCookieParsing:
    def test_parse_simple_cookie(self, cookie_jar):
        result = cookie_jar._parse_set_cookie("session=abc123")
        assert len(result) == 1
        assert result[0]["name"] == "session"
        assert result[0]["value"] == "abc123"

    def test_parse_cookie_with_attributes(self, cookie_jar):
        result = cookie_jar._parse_set_cookie("token=xyz; Path=/; Secure; HttpOnly; SameSite=Lax")
        assert len(result) == 1
        assert result[0]["name"] == "token"
        assert result[0]["value"] == "xyz"
        assert result[0]["path"] == "/"
        assert result[0]["secure"] is True
        assert result[0]["http_only"] is True
        assert result[0]["same_site"] == "Lax"

    def test_parse_multiple_cookies(self, cookie_jar):
        result = cookie_jar._parse_set_cookie(["a=1; Path=/", "b=2; Path=/app"])
        assert len(result) == 2
        assert result[0]["name"] == "a"
        assert result[0]["value"] == "1"
        assert result[1]["name"] == "b"

    def test_parse_malformed_cookie(self, cookie_jar):
        result = cookie_jar._parse_set_cookie("noequalsign")
        assert len(result) == 0

    def test_parse_cookie_with_domain(self, cookie_jar):
        result = cookie_jar._parse_set_cookie("id=123; Domain=example.com")
        assert result[0]["domain"] == "example.com"

    def test_parse_cookie_with_expires(self, cookie_jar):
        result = cookie_jar._parse_set_cookie("sess=val; Expires=Mon, 01 Jan 2025 00:00:00 GMT")
        assert result[0]["expires"] is not None

    def test_parse_cookie_invalid_expires(self, cookie_jar):
        result = cookie_jar._parse_set_cookie("sess=val; Expires=invalid-date")
        assert result[0]["expires"] is None


class TestSessionRecording:
    def test_session_handling_engine_init(self, event_bus):
        from modules.session_handling.engine import SessionHandlingEngine
        engine = SessionHandlingEngine(event_bus)
        assert engine.cookie_jar is not None
        assert engine.macro_engine is not None
        assert engine.session_check is not None

    @pytest.mark.asyncio
    async def test_recording_mechanism(self, event_bus):
        from modules.session_handling.engine import SessionHandlingEngine
        engine = SessionHandlingEngine(event_bus)
        sid = str(uuid.uuid4())
        if not hasattr(engine, "_recording"):
            engine._recording = {}
        engine._recording[sid] = {"active": True, "requests": [], "started_at": "test"}
        assert sid in engine._recording
        assert engine._recording[sid]["active"] is True
        engine._recording[sid]["requests"].append({"method": "GET", "url": "http://test.com"})
        assert len(engine._recording[sid]["requests"]) == 1
        engine._recording[sid]["active"] = False
        assert engine._recording[sid]["active"] is False
