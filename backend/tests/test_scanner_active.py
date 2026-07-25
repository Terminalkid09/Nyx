import pytest
from unittest.mock import patch, AsyncMock
from modules.scanner.base_check import CheckResult


BASE_REQUEST = {
    "method": "GET",
    "url": "http://example.com/page?foo=bar&id=1",
    "headers": {"Host": "example.com"},
}


class TestActiveCheckBasics:
    def test_all_checks_instantiable(self):
        from modules.scanner.active.checks import (
            lfi, xss, sqli, ssrf, xxe,
            cache_deception, cors_misconfig_active, csrf_active,
            host_header_injection, hpp, idor, jwt_none_active,
            ldap_injection, nosqli, oauth_misconfig, open_redirect,
            parameter_pollution, race_condition, request_smuggling,
            session_fixation, ssti, xpath_injection, xst,
        )
        checks = [
            lfi.LfiCheck(),
            xss.XssCheck(),
            sqli.SQLiCheck(),
            ssrf.SsrfCheck(),
            xxe.XxeCheck(),
            cache_deception.CacheDeceptionCheck(),
            cors_misconfig_active.CorsMisconfigActiveCheck(),
            csrf_active.CsrfActiveCheck(),
            host_header_injection.HostHeaderInjectionCheck(),
            hpp.HppCheck(),
            idor.IdorCheck(),
            jwt_none_active.JwtNoneActiveCheck(),
            ldap_injection.LdapInjectionCheck(),
            nosqli.NoSqlInjectionCheck(),
            oauth_misconfig.OAuthMisconfigCheck(),
            open_redirect.OpenRedirectCheck(),
            parameter_pollution.ParameterPollutionCheck(),
            race_condition.RaceConditionCheck(),
            request_smuggling.RequestSmugglingCheck(),
            session_fixation.SessionFixationCheck(),
            ssti.SstiCheck(),
            xpath_injection.XPathInjectionCheck(),
            xst.XstCheck(),
        ]
        for c in checks:
            assert isinstance(c.name, str) and c.name, (
                f"{type(c).__name__} has empty name"
            )


class TestLfiCheck:
    @pytest.fixture
    def check(self):
        from modules.scanner.active.checks.lfi import LfiCheck
        return LfiCheck()

    @pytest.mark.asyncio
    async def test_lfi_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) >= 1
            assert "LFI" in results[0].title or "lfi" in results[0].title.lower()
            assert results[0].severity == "high"

    @pytest.mark.asyncio
    async def test_lfi_not_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = "Hello world"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_param_not_in_url(self, check):
        mock_response = AsyncMock()
        mock_response.text = "normal response"
        mock_response.status_code = 200
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["nonexistent"])
            assert len(results) == 0


class TestXssCheck:
    @pytest.fixture
    def check(self):
        from modules.scanner.active.checks.xss import XssCheck
        return XssCheck()

    @pytest.mark.asyncio
    async def test_xss_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = '<script>alert(1)</script>'
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) >= 1
            assert "XSS" in results[0].title or "xss" in results[0].title.lower()
            assert results[0].severity == "high"

    @pytest.mark.asyncio
    async def test_xss_not_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = "safe content"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/plain"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_xss_wrong_content_type(self, check):
        mock_response = AsyncMock()
        mock_response.text = "<script>alert(1)</script>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) == 0


class TestSQLiCheck:
    @pytest.fixture
    def check(self):
        from modules.scanner.active.checks.sqli import SQLiCheck
        return SQLiCheck()

    @pytest.mark.asyncio
    async def test_sqli_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = "You have an error in your SQL syntax"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) >= 1
            assert "SQL" in results[0].title
            assert results[0].severity == "high"

    @pytest.mark.asyncio
    async def test_sqli_timeout_blind(self, check):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.side_effect = __import__("httpx").TimeoutException(
            "timeout"
        )

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            blind = [r for r in results if "blind" in r.title.lower()]
            assert len(blind) >= 1

    @pytest.mark.asyncio
    async def test_no_sqli(self, check):
        mock_response = AsyncMock()
        mock_response.text = "Hello world"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) == 0


class TestSsrfCheck:
    @pytest.fixture
    def check(self):
        from modules.scanner.active.checks.ssrf import SsrfCheck
        return SsrfCheck()

    @pytest.mark.asyncio
    async def test_ssrf_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) >= 1
            assert "SSRF" in results[0].title
            assert results[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_ssrf(self, check):
        mock_response = AsyncMock()
        mock_response.text = "normal response"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) == 0


class TestXxeCheck:
    @pytest.fixture
    def check(self):
        from modules.scanner.active.checks.xxe import XxeCheck
        return XxeCheck()

    @pytest.mark.asyncio
    async def test_xxe_detected(self, check):
        mock_response = AsyncMock()
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) >= 1
            assert "XXE" in results[0].title
            assert results[0].severity == "high"

    @pytest.mark.asyncio
    async def test_no_xxe(self, check):
        mock_response = AsyncMock()
        mock_response.text = "normal response"
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.request.return_value = mock_response

        with patch("httpx.AsyncClient", return_value=mock_client):
            results = await check.run(BASE_REQUEST, ["foo"])
            assert len(results) == 0
