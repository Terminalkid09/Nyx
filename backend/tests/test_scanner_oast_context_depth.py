"""Tests for OAST detection, context-aware XSS, and scan depth profiles."""
import pytest


class TestActiveOast:
    def test_module_imports(self):
        from modules.scanner.active.checks.active_oast import ActiveOastCheck
        check = ActiveOastCheck()
        assert check.name == "active_oast"

    def test_payloads_structure(self):
        from modules.scanner.active.checks.active_oast import _OAST_PAYLOADS
        assert "ssrf" in _OAST_PAYLOADS
        assert "xxe" in _OAST_PAYLOADS
        assert "log4shell" in _OAST_PAYLOADS
        assert "sqli-mssql" in _OAST_PAYLOADS
        for cls, payloads in _OAST_PAYLOADS.items():
            assert all("{subdomain}" in p for p in payloads), f"{cls} payloads must reference subdomain"

    def test_classify_callback(self):
        from modules.scanner.active.checks.active_oast import ActiveOastCheck
        check = ActiveOastCheck()
        assert check._classify_callback("http://abc.localhost/xxe") == "xxe"
        assert check._classify_callback("http://abc.localhost/ssrf-probe") == "ssrf"
        assert check._classify_callback("ldap://abc.localhost/a") == "log4shell"
        assert check._classify_callback("http://abc.localhost/unknown") == "ssrf"

    def test_remediation_for(self):
        from modules.scanner.active.checks.active_oast import ActiveOastCheck
        check = ActiveOastCheck()
        assert "allowlist" in check._remediation_for("ssrf")
        assert "XML" in check._remediation_for("xxe")
        assert "Log4j" in check._remediation_for("log4shell")
        assert "parameterized" in check._remediation_for("sqli")

    def test_inject_payload(self):
        from modules.scanner.active.checks.active_oast import ActiveOastCheck
        from urllib.parse import unquote
        check = ActiveOastCheck()
        base = {"url": "http://example.com/page?url=http://normal", "method": "GET"}
        modified = check._inject_payload(base, "url", "http://abc.localhost/")
        assert "abc.localhost" in unquote(modified["url"])


class TestActiveXssContext:
    def test_module_imports(self):
        from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
        check = ActiveXssContextCheck()
        assert check.name == "active_xss_context"

    def test_canary_generation(self):
        from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
        c1 = ActiveXssContextCheck._canary()
        c2 = ActiveXssContextCheck._canary()
        assert len(c1) == 10
        assert c1 != c2  # random

    def test_detect_context_attr_double(self):
        from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
        check = ActiveXssContextCheck()
        canary = "abc123defg"
        body = f'<input type="text" value="{canary}">'
        assert check._detect_context(body, canary) == "attr_double"

    def test_detect_context_text_node(self):
        from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
        check = ActiveXssContextCheck()
        canary = "abc123defg"
        body = f'<div>Hello {canary} world</div>'
        assert check._detect_context(body, canary) == "text_node"

    def test_detect_context_js_string(self):
        from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
        check = ActiveXssContextCheck()
        canary = "abc123defg"
        body = f'<script>var x = "{canary}";</script>'
        assert check._detect_context(body, canary) == "js_string"

    def test_detect_context_not_reflected(self):
        from modules.scanner.active.checks.active_xss_context import ActiveXssContextCheck
        check = ActiveXssContextCheck()
        assert check._detect_context("<div>nothing</div>", "missing") is None

    def test_context_payloads_complete(self):
        from modules.scanner.active.checks.active_xss_context import _CONTEXT_PAYLOADS
        required = {"attr_double", "attr_single", "text_node", "js_string", "js_template", "url_attr", "event_handler", "style"}
        assert required <= set(_CONTEXT_PAYLOADS.keys())


class TestScanDepth:
    def test_get_depth_default(self):
        from modules.scanner.scan_depth import get_depth, DEFAULT_DEPTH
        assert get_depth(None).name == DEFAULT_DEPTH
        assert get_depth("unknown").name == DEFAULT_DEPTH

    def test_get_depth_profiles(self):
        from modules.scanner.scan_depth import get_depth
        assert get_depth("fast").name == "fast"
        assert get_depth("balanced").name == "balanced"
        assert get_depth("deep").name == "deep"

    def test_fast_skips_heavy(self):
        from modules.scanner.scan_depth import get_depth
        fast = get_depth("fast")
        assert fast.include_heavy is False
        assert fast.skip_check("active_time_blind") is True
        assert fast.skip_check("active_oast") is True
        assert fast.skip_check("active_sqli_blind") is True
        assert fast.skip_check("active_xss") is False  # fast check still runs

    def test_deep_keeps_heavy(self):
        from modules.scanner.scan_depth import get_depth
        deep = get_depth("deep")
        assert deep.include_heavy is True
        assert deep.skip_check("active_time_blind") is False
        assert deep.max_payloads_per_param > 20

    def test_list_depths(self):
        from modules.scanner.scan_depth import list_depths
        depths = list_depths()
        assert "fast" in depths
        assert "balanced" in depths
        assert "deep" in depths

    def test_payload_caps(self):
        from modules.scanner.scan_depth import get_depth
        assert get_depth("fast").max_payloads_per_param < get_depth("balanced").max_payloads_per_param
        assert get_depth("balanced").max_payloads_per_param < get_depth("deep").max_payloads_per_param


class TestActiveScannerDepthIntegration:
    def test_run_checks_signature_has_depth(self):
        import inspect
        from modules.scanner.active.scanner import ActiveScanner
        sig = inspect.signature(ActiveScanner.run_checks)
        assert "depth" in sig.parameters

    def test_api_depth_endpoint(self):
        from api.routes.active_scanner import router
        routes = [r.path for r in router.routes]
        assert "/api/active-scanner/depths" in routes

    def test_api_request_has_depth(self):
        from api.routes.active_scanner import ActiveScanRequest
        assert "depth" in ActiveScanRequest.model_fields