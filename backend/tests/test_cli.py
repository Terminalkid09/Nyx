"""F-02: headless CLI contract."""
import json

import pytest

import nyx_cli


class FakeScanner:
    last_call = None

    def __init__(self, event_bus=None):
        self.checks = []
        self._checks = []

    async def run_checks(self, base_request, params, event=None, depth=None,
                         deadline_seconds=None, **kwargs):
        FakeScanner.last_call = {
            "base_request": base_request, "params": params,
            "event": event, "depth": depth,
            "deadline_seconds": deadline_seconds,
        }
        return [
            {"check": "active_sqli", "severity": "high", "title": "SQLi"},
            {"check": "active_hsts", "severity": "low", "title": "HSTS"},
        ]


def test_severity_threshold():
    assert nyx_cli.severity_at_least("critical", "high") is True
    assert nyx_cli.severity_at_least("high", "high") is True
    assert nyx_cli.severity_at_least("medium", "high") is False
    assert nyx_cli.severity_at_least("bogus", "high") is False


def test_build_base_request_merges_headers():
    request = nyx_cli.build_base_request(
        "https://example.com/", "post", ["X-Test: 1", "Accept: */*"], "a=1"
    )
    assert request["method"] == "POST"
    assert request["headers"]["X-Test"] == "1"
    assert request["headers"]["Accept"] == "*/*"
    assert request["headers"]["User-Agent"].startswith("Nyx-CLI")
    assert request["body"] == "a=1"


def test_summarise_counts_and_threshold():
    findings = [{"severity": "high"}, {"severity": "low"}, {"severity": "high"}]
    summary = nyx_cli.summarise(findings, "high")
    assert summary["total"] == 3
    assert summary["by_severity"]["high"] == 2
    assert summary["failing"] == 2
    assert summary["passed"] is False


def test_cli_exit_one_when_threshold_met(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "modules.scanner.active.scanner.ActiveScanner", FakeScanner
    )
    out = tmp_path / "report.json"
    code = nyx_cli.main([
        "scan", "--url", "https://example.com/", "--fail-on", "high",
        "--out", str(out),
    ])
    assert code == 1
    report = json.loads(out.read_text())
    assert report["summary"]["failing"] == 1
    assert FakeScanner.last_call["event"] == {"session_id": None}


def test_cli_exit_zero_when_below_threshold(monkeypatch):
    monkeypatch.setattr(
        "modules.scanner.active.scanner.ActiveScanner", FakeScanner
    )
    code = nyx_cli.main([
        "scan", "--url", "https://example.com/", "--fail-on", "critical",
    ])
    assert code == 0


def test_cli_invalid_url_returns_two(monkeypatch):
    class BrokenScanner(FakeScanner):
        async def run_checks(self, *args, **kwargs):
            raise ValueError("bad url")

    monkeypatch.setattr(
        "modules.scanner.active.scanner.ActiveScanner", BrokenScanner
    )
    assert nyx_cli.main(["scan", "--url", "https://example.com/"]) == 2


def test_extract_params_from_query_and_json_body():
    assert nyx_cli.extract_params("https://x.test/a?q=1&id=2") == ["q", "id"]
    assert nyx_cli.extract_params(
        "https://x.test/a", '{"email": "a@b.c", "role": "user"}'
    ) == ["email", "role"]


def test_extract_params_from_form_body():
    assert nyx_cli.extract_params(
        "https://x.test/login", "username=admin&password=x"
    ) == ["username", "password"]


def test_cli_tests_parameters_found_in_the_url(monkeypatch):
    monkeypatch.setattr("modules.scanner.active.scanner.ActiveScanner", FakeScanner)
    FakeScanner.last_call = None

    code = nyx_cli.main([
        "scan", "--url", "https://example.com/search?q=test", "--fail-on", "critical",
    ])

    assert code == 0
    assert FakeScanner.last_call["params"] == ["q"]
