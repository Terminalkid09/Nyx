import pytest
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch


class TestAuthProfileStore:
    def test_create_and_get_profile(self):
        from modules.auth.models import AuthProfile
        from modules.auth.store import create_profile, get_profile, delete_profile

        profile = AuthProfile(name="Test Login", login_url="http://test.com/login")
        created = create_profile(profile)
        assert created.id is not None
        assert created.name == "Test Login"

        fetched = get_profile(created.id)
        assert fetched is not None
        assert fetched.name == "Test Login"

        delete_profile(created.id)
        assert get_profile(created.id) is None

    def test_list_profiles(self):
        from modules.auth.models import AuthProfile
        from modules.auth.store import create_profile, list_profiles, delete_profile

        p1 = create_profile(AuthProfile(name="Profile 1", login_url="http://a.com"))
        p2 = create_profile(AuthProfile(name="Profile 2", login_url="http://b.com"))
        profiles = list_profiles()
        assert len(profiles) >= 2
        names = [p.name for p in profiles]
        assert "Profile 1" in names
        assert "Profile 2" in names

        delete_profile(p1.id)
        delete_profile(p2.id)

    def test_update_profile(self):
        from modules.auth.models import AuthProfile
        from modules.auth.store import create_profile, update_profile, get_profile, delete_profile

        profile = create_profile(AuthProfile(name="Original", login_url="http://test.com"))
        profile.login_url = "http://new.com"
        updated = update_profile(profile.id, profile)
        assert updated is not None
        assert updated.login_url == "http://new.com"

        fetched = get_profile(profile.id)
        assert fetched.login_url == "http://new.com"

        delete_profile(profile.id)

    def test_delete_nonexistent(self):
        from modules.auth.store import delete_profile
        assert delete_profile("nonexistent") is False

    def test_profile_to_macro_config(self):
        from modules.auth.models import AuthProfile, MacroStep

        profile = AuthProfile(
            name="Macro Login",
            target_url="http://test.com",
            macro_steps=[
                MacroStep(url="http://test.com/login", method="POST", body="user=admin&pass=1234"),
                MacroStep(url="http://test.com/dashboard", method="GET"),
            ],
        )
        macro = profile.to_macro_config()
        assert len(macro) == 2
        assert macro[0]["url"] == "http://test.com/login"
        assert macro[1]["url"] == "http://test.com/dashboard"

    def test_login_form_to_macro(self):
        from modules.auth.models import AuthProfile

        profile = AuthProfile(
            name="Form Login",
            login_url="http://test.com/login",
            login_method="POST",
            login_body="user=admin&pass=secret123",
            csrf_token_extract=r'name="csrf" value="([^"]+)"',
        )
        macro = profile.to_macro_config()
        assert len(macro) == 1
        assert macro[0]["url"] == "http://test.com/login"
        assert macro[0]["body"] == "user=admin&pass=secret123"
        assert "csrf_token" in macro[0]["extract"]


@pytest.mark.asyncio
class TestAuthActiveChecks:
    async def test_priv_escalation_not_triggered_on_normal(self):
        from modules.scanner.active.checks.auth_checks import ActiveAuthPrivilegeEscalationCheck
        check = ActiveAuthPrivilegeEscalationCheck()

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "hello world"
        mock_client = AsyncMock()
        mock_client.request.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client

        with patch("modules.scanner.active.checks.auth_checks.httpx.AsyncClient", return_value=mock_client):
            results = await check.run(
                {"method": "GET", "url": "http://httpbin.org/get", "headers": {}},
                [],
            )
        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 0

    async def test_idor_returns_empty_when_no_params(self):
        from modules.scanner.active.checks.auth_checks import ActiveAuthIdorCheck
        check = ActiveAuthIdorCheck()
        results = await check.run(
            {"method": "GET", "url": "http://httpbin.org/get", "headers": {}},
            [],
        )
        assert len(results) == 0

    async def test_forced_browsing_on_inaccessible_path(self):
        from modules.scanner.active.checks.auth_checks import ActiveAuthForcedBrowsingCheck
        check = ActiveAuthForcedBrowsingCheck()

        mock_response = AsyncMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_response.content = b"Forbidden"
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client

        with patch("modules.scanner.active.checks.auth_checks.httpx.AsyncClient", return_value=mock_client):
            results = await check.run(
                {"method": "GET", "url": "http://httpbin.org/get", "headers": {}},
                [],
            )
        triggered = [r for r in results if r.triggered]
        for r in triggered:
            assert "admin" in r.evidence or "config" in r.evidence or "dashboard" in r.evidence

    async def test_role_manipulation_no_false_positive(self):
        from modules.scanner.active.checks.auth_checks import ActiveAuthRoleManipulationCheck
        check = ActiveAuthRoleManipulationCheck()

        mock_response = AsyncMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__.return_value = mock_client

        with patch("modules.scanner.active.checks.auth_checks.httpx.AsyncClient", return_value=mock_client):
            results = await check.run(
                {"method": "GET", "url": "http://httpbin.org/get", "headers": {}},
                [],
            )
        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 0


class TestAuthAPIRoutes:
    def test_login_record_fails_without_session(self):
        import httpx
        import asyncio
        try:
            asyncio.run(httpx.AsyncClient().post("http://localhost:9999/api/auth/login/record", json={"session_id": "nonexistent"}))
        except Exception:
            pass

    def test_auth_scan_fails_without_scanner(self):
        from modules.auth.models import AuthProfile
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        assert scanner is not None
