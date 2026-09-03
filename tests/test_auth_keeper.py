"""
Unit tests for the Auth Keeper module.
Tests credential extraction, login detection, and session refresh logic.
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from core.events.bus import EventBus
from modules.scanner.auth_keeper import AuthKeeper, LoginCandidate


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def keeper(event_bus):
    return AuthKeeper(event_bus)


# ── Credential Extraction Tests ─────────────────────────────────────────────

class TestCredentialExtraction:

    def test_extracts_bearer_token_from_json_body(self, keeper):
        body = json.dumps({"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"})
        creds = keeper._extract_credentials(body, {})
        assert creds is not None
        assert "bearer" in creds
        assert creds["bearer"].startswith("eyJ")

    def test_extracts_token_key_from_json_body(self, keeper):
        body = json.dumps({"token": "some-opaque-token-value"})
        creds = keeper._extract_credentials(body, {})
        assert creds is not None
        assert creds["bearer"] == "some-opaque-token-value"

    def test_extracts_session_cookie_from_set_cookie_header(self, keeper):
        headers = {"set-cookie": "session=abc123def456; Path=/; HttpOnly"}
        creds = keeper._extract_credentials("", headers)
        assert creds is not None
        assert "cookies" in creds
        assert creds["cookies"]["session"] == "abc123def456"

    def test_extracts_multiple_cookies(self, keeper):
        headers = {"set-cookie": "session=abc; token=xyz; Path=/"}
        creds = keeper._extract_credentials("", headers)
        assert creds is not None
        assert len(creds.get("cookies", {})) >= 1

    def test_returns_none_if_no_credentials(self, keeper):
        creds = keeper._extract_credentials("<html>not a login page</html>", {})
        assert creds is None

    def test_applies_bearer_to_headers(self, keeper):
        creds = {"bearer": "mytoken123"}
        result = keeper._apply_credentials({}, creds)
        assert result.get("Authorization") == "Bearer mytoken123"

    def test_applies_cookies_to_headers(self, keeper):
        creds = {"cookies": {"session": "abc", "csrf": "xyz"}}
        result = keeper._apply_credentials({}, creds)
        assert "Cookie" in result
        assert "session=abc" in result["Cookie"]

    def test_does_not_mutate_original_headers(self, keeper):
        original = {"X-Custom": "value"}
        creds = {"bearer": "token"}
        keeper._apply_credentials(original, creds)
        assert "Authorization" not in original


# ── Login Detection Tests ────────────────────────────────────────────────────

class TestLoginDetection:

    def test_detects_post_to_login(self):
        assert AuthKeeper._is_login_request("POST", "https://example.com/login") is True

    def test_detects_post_to_auth(self):
        assert AuthKeeper._is_login_request("POST", "https://example.com/api/auth") is True

    def test_detects_post_to_signin(self):
        assert AuthKeeper._is_login_request("POST", "https://example.com/signin") is True

    def test_detects_post_to_token(self):
        assert AuthKeeper._is_login_request("POST", "https://example.com/oauth/token") is True

    def test_ignores_get_to_login(self):
        assert AuthKeeper._is_login_request("GET", "https://example.com/login") is False

    def test_ignores_post_to_non_auth_path(self):
        assert AuthKeeper._is_login_request("POST", "https://example.com/api/products") is False


# ── Event Bus Integration Tests ─────────────────────────────────────────────

@pytest.mark.asyncio
class TestAuthKeeperEvents:

    async def test_captures_login_candidate_on_request_event(self, keeper, event_bus):
        await event_bus.publish({
            "type": "request.captured",
            "session_id": "test-session-1",
            "method": "POST",
            "url": "https://example.com/api/auth/login",
            "request_headers": {"Content-Type": "application/json"},
            "request_body": '{"username":"admin","password":"secret"}',
        })
        # Allow async tasks to run
        await asyncio.sleep(0.05)
        assert "test-session-1" in keeper._candidates

    async def test_caches_credentials_on_successful_login_response(self, keeper, event_bus):
        # First, capture a login request so there's a candidate
        await event_bus.publish({
            "type": "request.captured",
            "session_id": "test-session-2",
            "method": "POST",
            "url": "https://example.com/login",
            "request_headers": {},
            "request_body": "user=test&pass=test",
        })
        await asyncio.sleep(0.05)

        # Now simulate a successful response
        await event_bus.publish({
            "type": "response.received",
            "session_id": "test-session-2",
            "status": 200,
            "body": '{"access_token": "new_jwt_token_value"}',
            "headers": {},
        })
        await asyncio.sleep(0.05)
        assert "test-session-2" in keeper._live_creds
        assert keeper._live_creds["test-session-2"]["bearer"] == "new_jwt_token_value"

    async def test_does_not_cache_on_failed_login(self, keeper, event_bus):
        await event_bus.publish({
            "type": "request.captured",
            "session_id": "test-session-3",
            "method": "POST",
            "url": "https://example.com/login",
            "request_headers": {},
            "request_body": "",
        })
        await asyncio.sleep(0.05)

        await event_bus.publish({
            "type": "response.received",
            "session_id": "test-session-3",
            "status": 401,
            "body": '{"error": "invalid credentials"}',
            "headers": {},
        })
        await asyncio.sleep(0.05)
        assert "test-session-3" not in keeper._live_creds

    async def test_emits_refresh_failed_when_no_candidate(self, keeper, event_bus):
        emitted_events = []
        event_bus.subscribe("auth_keeper.refresh_failed", lambda e: emitted_events.append(e) or asyncio.coroutine(lambda: None)())

        async def capture(e):
            emitted_events.append(e)

        event_bus.subscribe("auth_keeper.refresh_failed", capture)

        await event_bus.publish({
            "type": "scan.auth_failure",
            "session_id": "nonexistent-session",
        })
        await asyncio.sleep(0.1)

        failure_events = [e for e in emitted_events if e.get("type") == "auth_keeper.refresh_failed"]
        assert len(failure_events) > 0
        assert failure_events[0]["reason"] == "no_login_candidate"


# ── Public API Tests ─────────────────────────────────────────────────────────

class TestPublicAPI:

    def test_patch_request_headers_returns_unchanged_if_no_creds(self, keeper):
        headers = {"Content-Type": "application/json"}
        result = keeper.patch_request_headers("unknown-session", headers)
        assert result == headers

    def test_patch_request_headers_adds_bearer(self, keeper):
        keeper._live_creds["sess-1"] = {"bearer": "freshtoken"}
        result = keeper.patch_request_headers("sess-1", {})
        assert result.get("Authorization") == "Bearer freshtoken"

    def test_get_credentials_returns_none_for_unknown_session(self, keeper):
        assert keeper.get_credentials("does-not-exist") is None

    def test_get_status_reflects_internal_state(self, keeper):
        keeper._candidates["s1"] = MagicMock()
        keeper._live_creds["s1"] = {"bearer": "tok"}
        status = keeper.get_status()
        assert "s1" in status["sessions_with_candidates"]
        assert "s1" in status["sessions_with_creds"]
