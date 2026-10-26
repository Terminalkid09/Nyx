"""BUG-13: relative links must be resolved against the request URL."""
import pytest

from modules.automation.engine import AutoScanEngine


def _engine() -> AutoScanEngine:
    return AutoScanEngine(event_bus=None, passive_scanner=None, active_scanner=None)


def test_relative_link_resolved_against_request_url():
    engine = _engine()
    engine._add_discovered(
        "/admin", "response_body", {"url": "https://example.com/app/page?x=1"}
    )
    assert list(engine.discovered_urls) == ["https://example.com/admin"]
    assert engine.discovered_urls["https://example.com/admin"]["host"] == "example.com"


def test_protocol_relative_link_uses_request_scheme():
    engine = _engine()
    engine._add_discovered(
        "//cdn.example.net/app.js", "response_body",
        {"url": "https://example.com/"},
    )
    assert list(engine.discovered_urls) == ["https://cdn.example.net/app.js"]


def test_scheme_less_url_rejected_without_base():
    engine = _engine()
    engine._add_discovered("/admin", "response_body", {})
    assert engine.discovered_urls == {}


@pytest.mark.parametrize("url", ["javascript:alert(1)", "mailto:a@b.c", "data:text/html,x"])
def test_non_http_schemes_rejected(url):
    engine = _engine()
    engine._add_discovered(url, "response_body", {"url": "https://example.com/"})
    assert engine.discovered_urls == {}
