import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestServerFingerprint:
    @pytest.mark.asyncio
    async def test_extract_version(self):
        from modules.scanner.fingerprint import _extract_version
        assert _extract_version("nginx/1.18.0") == "1.18.0"
        assert _extract_version("Apache/2.4.41") == "2.4.41"
        assert _extract_version("Microsoft-IIS/10.0") == "10.0"
        assert _extract_version("cloudflare") == ""

    def test_select_checks_for_target_empty(self):
        from modules.scanner.fingerprint import select_checks_for_target
        result = select_checks_for_target({"technologies": []})
        assert result == {"prioritize": [], "skip": []}

    def test_select_checks_for_target_apache(self):
        from modules.scanner.fingerprint import select_checks_for_target
        result = select_checks_for_target({"technologies": ["apache", "php"]})
        assert "active_default_admin" in result["prioritize"]
        assert "active_default_admin2" in result["prioritize"]

    def test_select_checks_for_target_wordpress(self):
        from modules.scanner.fingerprint import select_checks_for_target
        result = select_checks_for_target({"technologies": ["wordpress", "php"]})
        assert "active_wordpress_enum" in result["prioritize"]

    def test_select_checks_for_target_nginx(self):
        from modules.scanner.fingerprint import select_checks_for_target
        result = select_checks_for_target({"technologies": ["nginx"]})
        assert "active_default_admin" in result["prioritize"]

    def test_select_checks_with_waf(self):
        from modules.scanner.fingerprint import select_checks_for_target
        result = select_checks_for_target({"technologies": ["apache"], "waf": ["cloudflare"]})
        assert "active_sqli" in result["skip"]
        assert "active_xss" in result["skip"]
        assert "note" in result


class TestFingerprintServer:
    @pytest.mark.asyncio
    async def test_fingerprint_http_error(self):
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=Exception("Connection failed"))
            mock_client.return_value.__aenter__.return_value = mock_instance
            from modules.scanner.fingerprint import fingerprint_server
            result = await fingerprint_server("http://invalid.local")
            assert "error" in result

    @pytest.mark.asyncio
    async def test_fingerprint_signatures(self):
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"server": "nginx/1.20.1", "x-powered-by": "PHP/7.4"}
            mock_response.text = "<html>wordpress</html>"
            mock_response.cookies.list = MagicMock(return_value=[])
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_instance
            from modules.scanner.fingerprint import fingerprint_server
            result = await fingerprint_server("http://example.com")
            assert result["server"] == "nginx/1.20.1"
            assert result["version"] == "1.20.1"
            assert "nginx" in result["technologies"]
            assert "php" in result["technologies"]
            assert "wordpress" in result["technologies"]


class TestActiveScannerEnhancements:
    def test_active_scanner_builds_checks(self):
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        checks = scanner.checks
        assert len(checks) > 80
        names = [c.name for c in checks]
        assert "active_sqli" in names
        assert "active_xss" in names
        assert "active_aws_keys" in names
        assert "active_log4shell" in names
        assert "active_git_exposed" in names
        assert "active_tomcat_manager" in names
        assert "active_prometheus_check" in names
        assert "active_kibana_check" in names
        assert "active_grafana_check" in names
        assert "active_http_methods" in names

    def test_new_checks_have_unique_names(self):
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        names = [c.name for c in scanner.checks]
        duplicates = [n for n in names if names.count(n) > 1]
        new_check_prefixes = ["active_aws_keys", "active_cors_credentials", "active_csp_bypass",
            "active_dir_listing", "active_dom_xss", "active_elb_check", "active_email_injection",
            "active_form_action_override", "active_git_exposed", "active_grafana_check",
            "active_graphql_batch", "active_h2c_smuggling", "active_header_injection",
            "active_hsts_missing", "active_http_methods", "active_jsource_exposed",
            "active_jwt_alg_confusion", "active_kibana_check", "active_log4shell",
            "active_open_bucket_check", "active_prometheus_check", "active_sqlmap_api",
            "active_ssti_blind", "active_svg_upload", "active_tomcat_manager",
            "active_traversal_encoded", "active_verb_tampering", "active_version_enum",
            "active_websocket_origin", "active_xss_dom_based"]
        for d in duplicates:
            assert d not in new_check_prefixes, f"New check name '{d}' collides with existing check"

    def test_all_checks_can_be_instantiated(self):
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        for check in scanner.checks:
            assert hasattr(check, "name"), f"{type(check).__name__} missing name"
            assert hasattr(check, "run"), f"{type(check).__name__} missing run"

    @pytest.mark.asyncio
    async def test_fingerprint_method(self):
        from modules.scanner.active.scanner import ActiveScanner
        from unittest.mock import patch, AsyncMock

        with patch("modules.scanner.active.scanner.fingerprint_server", new_callable=AsyncMock) as mock_fp:
            mock_fp.return_value = {"server": "nginx", "version": "1.20.1", "technologies": ["nginx"]}
            scanner = ActiveScanner()
            result = await scanner.fingerprint("http://test.com")
            assert result["server"] == "nginx"
            assert result["version"] == "1.20.1"

    @pytest.mark.asyncio
    async def test_discover_params_method_empty(self):
        from modules.scanner.active.scanner import ActiveScanner
        scanner = ActiveScanner()
        result = await scanner.discover_params("http://test.com")
        assert isinstance(result, list)
