"""SEC-02: the report download endpoint must not read outside reports_dir."""
import json

import pytest

from reporter.service import ReporterService


@pytest.fixture
def reporter(tmp_path, monkeypatch):
    service = ReporterService()
    monkeypatch.setattr(service, "reports_dir", tmp_path)
    return service


def test_reads_report_inside_dir(reporter, tmp_path):
    (tmp_path / "report.json").write_text(json.dumps({"ok": True}))
    assert reporter.get_report_content("report.json") == {"ok": True}


@pytest.mark.parametrize(
    "payload",
    [
        "../outside.json",
        "..\\outside.json",
        "../../etc/passwd.json",
        "subdir/report.json",
        "/etc/passwd.json",
        "",
    ],
)
def test_rejects_traversal_and_separators(reporter, payload):
    assert reporter.get_report_content(payload) is None


def test_rejects_absolute_path_outside_dir(reporter, tmp_path):
    outside = tmp_path.parent / "nyx_outside_secret.json"
    outside.write_text(json.dumps({"secret": "leaked"}))
    try:
        assert reporter.get_report_content(str(outside)) is None
    finally:
        outside.unlink(missing_ok=True)


def test_rejects_unsupported_extension(reporter, tmp_path):
    (tmp_path / "secret.txt").write_text("nope")
    assert reporter.get_report_content("secret.txt") is None
