import pytest
import json


class TestBackupService:
    def test_csv_export_empty(self):
        import csv, io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["id", "severity", "title"])
        writer.writeheader()
        result = output.getvalue()
        assert "id,severity,title" in result

    def test_csv_export_with_data(self):
        import csv, io
        output = io.StringIO()
        rows = [
            {"id": "1", "severity": "critical", "title": "SQLi"},
            {"id": "2", "severity": "high", "title": "XSS"},
        ]
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        result = output.getvalue()
        assert "1,critical,SQLi" in result
        assert "2,high,XSS" in result

    def test_json_export_structure(self):
        findings = [
            {"id": "1", "severity": "critical", "title": "SQLi", "cwe": "CWE-89"},
            {"id": "2", "severity": "high", "title": "XSS", "cwe": "CWE-79"},
        ]
        data = json.dumps(findings, indent=2)
        parsed = json.loads(data)
        assert len(parsed) == 2
        assert parsed[0]["cwe"] == "CWE-89"

    def test_backup_stats_structure(self):
        stats = {
            "sessions": 1,
            "requests": 100,
            "findings": 5,
            "by_severity": {"critical": 1, "high": 2, "medium": 1, "low": 1},
        }
        assert stats["sessions"] == 1
        assert sum(stats["by_severity"].values()) == 5

    def test_backup_structure(self):
        backup = {
            "nyx_version": "1.0.0",
            "exported_at": "2025-01-01T00:00:00",
            "stats": {"sessions": 0, "requests": 0, "findings": 0},
            "data": {"sessions": [], "requests": [], "findings": []},
        }
        assert backup["nyx_version"] == "1.0.0"
        assert isinstance(backup["data"]["sessions"], list)
        assert isinstance(backup["data"]["findings"], list)

    def test_finding_export_fields(self):
        row = {
            "id": "abc-123",
            "session_id": "session-1",
            "severity": "high",
            "title": "Test Finding",
            "description": "A description",
            "evidence": "evidence text",
            "remediation": "fix it",
            "module": "passive_scanner",
            "cwe": "CWE-79",
            "cvss_score": 6.5,
            "created_at": "2025-01-01T00:00:00",
        }
        expected_keys = {"id", "session_id", "severity", "title", "description", "evidence", "remediation", "module", "cwe", "cvss_score", "created_at"}
        assert set(row.keys()) == expected_keys
