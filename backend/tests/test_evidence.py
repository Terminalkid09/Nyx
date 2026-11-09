"""Evidence must be replayable without leaking credentials."""
from types import SimpleNamespace

from core.storage.evidence import build_curl, build_evidence, build_response_excerpt


def test_build_curl_from_passive_event():
    event = {
        "method": "GET",
        "url": "https://example.com/search?q=test",
        "request_headers": {"User-Agent": "Nyx", "Authorization": "Bearer secret"},
        "request_body": None,
    }
    curl = build_curl(event)
    assert curl.startswith("curl -i -X GET 'https://example.com/search?q=test'")
    assert "-H 'User-Agent: Nyx'" in curl
    assert "Bearer secret" not in curl
    assert "[REDACTED]" in curl


def test_build_curl_from_active_base_request():
    event = {
        "method": "POST",
        "url": "https://example.com/api",
        "headers": {"Content-Type": "application/json"},
        "body": '{"a": 1}',
    }
    curl = build_curl(event)
    assert "--data-raw" in curl
    assert '{"a": 1}' in curl


def test_build_curl_requires_absolute_url():
    assert build_curl({"url": "/relative", "method": "GET"}) is None


def test_response_excerpt_truncates():
    excerpt = build_response_excerpt({"status": 500, "body": "x" * 5000})
    assert excerpt.startswith("# response: 500")
    assert "truncated" in excerpt


def test_build_evidence_combines_parts():
    result = SimpleNamespace(evidence="payload: ' OR 1=1")
    event = {"method": "GET", "url": "https://example.com/?id=1", "status": 500, "body": "err"}
    merged = build_evidence(result, event)
    assert "payload:" in merged
    assert "Reproduce:" in merged
    assert "# response: 500" in merged


def test_build_evidence_returns_existing_when_no_request():
    result = SimpleNamespace(evidence="only this")
    assert build_evidence(result, {}) == "only this"
