import pytest
from modules.scanner.base_check import BaseCheck, CheckResult


def _all_passive_checks():
    from modules.scanner.passive.checks import (
        cookie_flags,
        cors_misconfig,
        info_leakage,
        jwt_none_alg,
        missing_headers,
        ssl_issues,
        sensitive_data_exposure,
        open_redirect_passive,
        clickjacking,
        hsts_check,
        cache_poisoning,
        csrf_tokens,
        directory_listing,
        email_disclosure,
        file_upload_misconfig,
        graphql_introspection,
        http_methods,
        insecure_cookies,
        jwt_exposure,
        open_bucket,
        openapi_exposure,
        path_traversal_passive,
        rate_limiting,
        security_txt,
        server_side_includes,
        subdomain_takeover,
        timing_headers,
        csp_eval,
    )
    return [
        cookie_flags.CookieFlagsCheck(),
        cors_misconfig.CorsMisconfigCheck(),
        info_leakage.InfoLeakageCheck(),
        jwt_none_alg.JwtNoneAlgCheck(),
        missing_headers.MissingHeadersCheck(),
        ssl_issues.SslIssuesCheck(),
        sensitive_data_exposure.SensitiveDataExposureCheck(),
        open_redirect_passive.OpenRedirectPassiveCheck(),
        clickjacking.ClickjackingCheck(),
        hsts_check.HstsCheck(),
        cache_poisoning.CachePoisoningCheck(),
        csrf_tokens.CsrfTokenCheck(),
        directory_listing.DirectoryListingCheck(),
        email_disclosure.EmailDisclosureCheck(),
        file_upload_misconfig.FileUploadMisconfigCheck(),
        graphql_introspection.GraphQLIntrospectionCheck(),
        http_methods.HttpMethodsCheck(),
        insecure_cookies.InsecureCookiesCheck(),
        jwt_exposure.JwtExposureCheck(),
        open_bucket.OpenBucketCheck(),
        openapi_exposure.OpenApiExposureCheck(),
        path_traversal_passive.PathTraversalPassiveCheck(),
        rate_limiting.RateLimitingCheck(),
        security_txt.SecurityTxtCheck(),
        server_side_includes.ServerSideIncludesCheck(),
        subdomain_takeover.SubdomainTakeoverCheck(),
        timing_headers.TimingHeadersCheck(),
        csp_eval.CspEvalCheck(),
    ]


class TestPassiveCheckBasics:
    def test_all_checks_have_name(self):
        for check in _all_passive_checks():
            assert isinstance(check.name, str) and check.name, (
                f"{type(check).__name__} has empty name"
            )

    @pytest.mark.asyncio
    async def test_all_checks_run_returns_list(self):
        event = {"headers": {}, "body": "", "status": 200}
        request_data = {"host": "example.com"}
        for check in _all_passive_checks():
            result = await check.run(event, request_data)
            assert isinstance(result, list), (
                f"{type(check).__name__}.run() did not return a list"
            )
            for r in result:
                assert isinstance(r, CheckResult)


class TestCookieFlags:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.cookie_flags import CookieFlagsCheck
        return CookieFlagsCheck()

    @pytest.mark.asyncio
    async def test_missing_all_flags(self, check):
        event = {
            "headers": {
                "Set-Cookie": "session=abc123; Path=/"
            }
        }
        results = await check.run(event, {})
        assert len(results) == 3
        titles = [r.title for r in results]
        assert any("Secure" in t for t in titles)
        assert any("HttpOnly" in t for t in titles)
        assert any("SameSite" in t for t in titles)

    @pytest.mark.asyncio
    async def test_all_flags_present(self, check):
        event = {
            "headers": {
                "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"
            }
        }
        results = await check.run(event, {})
        assert len(results) == 0


class TestCorsMisconfig:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.cors_misconfig import CorsMisconfigCheck
        return CorsMisconfigCheck()

    @pytest.mark.asyncio
    async def test_wildcard_with_credentials_high(self, check):
        event = {
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        }
        results = await check.run(event, {})
        assert len(results) >= 1
        high = [r for r in results if r.severity == "high"]
        assert len(high) == 1
        assert "wildcard origin with credentials" in high[0].title.lower()

    @pytest.mark.asyncio
    async def test_wildcard_only_medium(self, check):
        event = {
            "headers": {
                "Access-Control-Allow-Origin": "*",
            }
        }
        results = await check.run(event, {})
        assert len(results) == 1
        assert results[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_safe_config(self, check):
        event = {
            "headers": {
                "Access-Control-Allow-Origin": "https://trusted.com",
            }
        }
        results = await check.run(event, {})
        assert len(results) == 0


class TestInfoLeakage:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.info_leakage import InfoLeakageCheck
        return InfoLeakageCheck()

    @pytest.mark.asyncio
    async def test_server_header_leak(self, check):
        event = {
            "headers": {"Server": "Apache/2.4.1"},
            "body": "",
        }
        results = await check.run(event, {})
        assert len(results) >= 1
        assert any("Apache" in r.title for r in results)

    @pytest.mark.asyncio
    async def test_stacktrace_in_body_high(self, check):
        event = {
            "headers": {},
            "body": "Traceback (most recent call last):\n  File \"app.py\", line 10, in <module>",
        }
        results = await check.run(event, {})
        assert len(results) >= 1
        high = [r for r in results if r.severity == "high"]
        assert len(high) == 1
        assert "Stack trace" in high[0].title

    @pytest.mark.asyncio
    async def test_no_leakage(self, check):
        event = {
            "headers": {"Content-Type": "text/html"},
            "body": "OK",
        }
        results = await check.run(event, {})
        assert len(results) == 0


class TestJwtNoneAlg:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.jwt_none_alg import JwtNoneAlgCheck
        return JwtNoneAlgCheck()

    @pytest.mark.asyncio
    async def test_jwt_with_alg_none(self, check, sample_jwt_none):
        event = {"body": sample_jwt_none, "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 1
        assert results[0].severity == "critical"
        assert "none" in results[0].title.lower()

    @pytest.mark.asyncio
    async def test_jwt_with_hs256(self, check, sample_jwt):
        event = {"body": sample_jwt, "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_no_jwt_in_body(self, check):
        event = {"body": "hello world", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 0


class TestMissingHeaders:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.missing_headers import MissingHeadersCheck
        return MissingHeadersCheck()

    @pytest.mark.asyncio
    async def test_all_security_headers_missing(self, check):
        event = {"headers": {"Content-Type": "text/html"}, "body": ""}
        results = await check.run(event, {})
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_all_present(self, check):
        event = {
            "headers": {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
            },
            "body": "",
        }
        results = await check.run(event, {})
        assert len(results) == 0


class TestSslIssues:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.ssl_issues import SslIssuesCheck
        return SslIssuesCheck()

    @pytest.mark.asyncio
    async def test_tls_1_0_finding(self, check):
        event = {"tls_version": "TLSv1.0", "tls_cipher": "", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 1
        assert results[0].severity == "medium"
        assert "TLSv1.0" in results[0].title

    @pytest.mark.asyncio
    async def test_weak_cipher_finding(self, check):
        event = {"tls_version": "TLSv1.2", "tls_cipher": "TLS_RSA_WITH_RC4_128_SHA", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 1
        assert results[0].severity == "high"
        assert "RC4" in results[0].title or "weak" in results[0].title.lower()

    @pytest.mark.asyncio
    async def test_secure_tls(self, check):
        event = {"tls_version": "TLSv1.3", "tls_cipher": "TLS_AES_256_GCM_SHA384", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 0


class TestSensitiveDataExposure:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.sensitive_data_exposure import SensitiveDataExposureCheck
        return SensitiveDataExposureCheck()

    @pytest.mark.asyncio
    async def test_aws_key_detected(self, check):
        event = {"body": "AKIA0123456789ABCDEF", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 1
        assert "AWS" in results[0].title

    @pytest.mark.asyncio
    async def test_email_detected(self, check):
        event = {"body": "Contact us at test@example.com", "headers": {}}
        results = await check.run(event, {})
        assert len(results) >= 1
        assert "Email" in results[0].title

    @pytest.mark.asyncio
    async def test_private_key_detected(self, check):
        event = {
            "body": "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----",
            "headers": {},
        }
        results = await check.run(event, {})
        assert len(results) == 1
        assert "Private key" in results[0].title

    @pytest.mark.asyncio
    async def test_no_sensitive_data(self, check):
        event = {"body": "Hello, this is a safe response", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_empty_body(self, check):
        event = {"body": "", "headers": {}}
        results = await check.run(event, {})
        assert len(results) == 0


class TestOpenRedirectPassive:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.open_redirect_passive import OpenRedirectPassiveCheck
        return OpenRedirectPassiveCheck()

    @pytest.mark.asyncio
    async def test_redirect_to_external_domain(self, check):
        event = {
            "status": 302,
            "headers": {"Location": "https://evil.com/phish"},
        }
        request_data = {"host": "example.com"}
        results = await check.run(event, request_data)
        assert len(results) == 1
        assert "redirect" in results[0].title.lower()

    @pytest.mark.asyncio
    async def test_redirect_to_same_domain(self, check):
        event = {
            "status": 302,
            "headers": {"Location": "https://example.com/login"},
        }
        request_data = {"host": "example.com"}
        results = await check.run(event, request_data)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_not_a_redirect(self, check):
        event = {"status": 200, "headers": {}}
        results = await check.run(event, {"host": "example.com"})
        assert len(results) == 0


class TestClickjacking:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.clickjacking import ClickjackingCheck
        return ClickjackingCheck()

    @pytest.mark.asyncio
    async def test_no_protection_headers(self, check):
        event = {"headers": {}, "body": ""}
        results = await check.run(event, {})
        assert len(results) == 1
        assert results[0].severity == "high"
        assert "Clickjacking" in results[0].title

    @pytest.mark.asyncio
    async def test_x_frame_options_deny(self, check):
        event = {"headers": {"X-Frame-Options": "DENY"}, "body": ""}
        results = await check.run(event, {})
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_permissive_xfo(self, check):
        event = {"headers": {"X-Frame-Options": "ALLOW-FROM https://evil.com"}, "body": ""}
        results = await check.run(event, {})
        assert len(results) >= 1
        assert any("Permissive" in r.title for r in results)

    @pytest.mark.asyncio
    async def test_csp_frame_ancestors(self, check):
        event = {"headers": {"Content-Security-Policy": "frame-ancestors 'self'"}, "body": ""}
        results = await check.run(event, {})
        low_xfo = [r for r in results if "X-Frame-Options header missing" in r.title]
        assert len(low_xfo) == 1
        assert low_xfo[0].severity == "low"


class TestHstsCheck:
    @pytest.fixture
    def check(self):
        from modules.scanner.passive.checks.hsts_check import HstsCheck
        return HstsCheck()

    @pytest.mark.asyncio
    async def test_hsts_missing(self, check):
        event = {"headers": {}, "body": ""}
        results = await check.run(event, {})
        assert len(results) == 1
        assert "missing" in results[0].title.lower()

    @pytest.mark.asyncio
    async def test_short_max_age(self, check):
        event = {
            "headers": {
                "Strict-Transport-Security": "max-age=86400"
            },
            "body": "",
        }
        results = await check.run(event, {})
        assert len(results) >= 1
        assert any("short" in r.title.lower() for r in results)

    @pytest.mark.asyncio
    async def test_full_hsts(self, check):
        event = {
            "headers": {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
            },
            "body": "",
        }
        results = await check.run(event, {})
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_missing_max_age_directive(self, check):
        event = {
            "headers": {
                "Strict-Transport-Security": "includeSubDomains"
            },
            "body": "",
        }
        results = await check.run(event, {})
        assert any("max-age" in r.title.lower() for r in results)
