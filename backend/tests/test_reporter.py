import pytest
import uuid


@pytest.fixture
def reporter():
    from reporter.service import ReporterService
    return ReporterService()


@pytest.fixture
def sample_findings():
    return [
        {
            "severity": "critical",
            "title": "SQL Injection",
            "description": "SQL injection in id parameter",
            "evidence": "id=1' OR '1'='1",
            "remediation": "Use parameterized queries",
            "cwe": "CWE-89",
            "module": "active_scanner",
        },
        {
            "severity": "high",
            "title": "XSS",
            "description": "Reflected XSS in search parameter",
            "evidence": "<script>alert(1)</script>",
            "remediation": "Encode output",
            "cwe": "CWE-79",
            "module": "passive_scanner",
        },
        {
            "severity": "medium",
            "title": "Missing HSTS",
            "description": "HSTS header not set",
            "evidence": None,
            "remediation": "Add Strict-Transport-Security header",
            "cwe": "CWE-523",
            "module": "passive_scanner",
        },
    ]


class TestReporterService:
    @pytest.mark.asyncio
    async def test_generate_json(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=100, format="json")
        import json
        data = json.loads(result.decode())
        assert data["total_findings"] == 3
        assert data["request_count"] == 100
        assert data["by_severity"]["critical"] == 1
        assert data["by_severity"]["high"] == 1
        assert data["by_severity"]["medium"] == 1
        assert str(sid) in data["session_id"]

    @pytest.mark.asyncio
    async def test_generate_html(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=50, format="html")
        html = result.decode()
        assert "<!DOCTYPE html>" in html
        assert "SQL Injection" in html
        assert "XSS" in html
        assert "Nyx" in html
        assert "CWE-89" in html

    @pytest.mark.asyncio
    async def test_generate_markdown(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=50, format="md")
        md = result.decode()
        assert "Nyx Security Assessment Report" in md
        assert "SQL Injection" in md
        assert "CWE-89" in md
        assert "|" in md

    @pytest.mark.asyncio
    async def test_generate_pdf_fallback_to_html(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=10, format="pdf")
        html = result.decode()
        assert "<!DOCTYPE html>" in html

    @pytest.mark.asyncio
    async def test_generate_empty_findings(self, reporter):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=[], request_count=0, format="json")
        import json
        data = json.loads(result.decode())
        assert data["total_findings"] == 0
        assert data["request_count"] == 0

    @pytest.mark.asyncio
    async def test_generate_unknown_format(self, reporter, sample_findings):
        with pytest.raises(ValueError, match="Unknown format"):
            await reporter.generate(session_id=uuid.uuid4(), findings=sample_findings, request_count=1, format="xml")

    @pytest.mark.asyncio
    async def test_severity_sorting(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=1, format="json")
        import json
        data = json.loads(result.decode())
        assert data["findings"][0]["severity"] == "critical"
        assert data["findings"][1]["severity"] == "high"
        assert data["findings"][2]["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_html_contains_summary_boxes(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=75, format="html")
        html = result.decode()
        assert "Total Findings" in html
        assert "Requests" in html

    @pytest.mark.asyncio
    async def test_html_contains_severity_chart(self, reporter, sample_findings):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=sample_findings, request_count=75, format="html")
        html = result.decode()
        assert "Severity Distribution" in html
        assert "chart-bar" in html

    @pytest.mark.asyncio
    async def test_generate_markdown_empty(self, reporter):
        sid = uuid.uuid4()
        result = await reporter.generate(session_id=sid, findings=[], request_count=0, format="md")
        md = result.decode()
        assert "Nyx Security Assessment Report" in md
        assert "No findings" in md or "0" in md

    @pytest.mark.asyncio
    async def test_reports_dir_created(self, reporter):
        assert reporter.reports_dir.exists()

    @pytest.mark.asyncio
    async def test_list_reports_empty(self, reporter):
        reports = reporter.list_reports()
        assert isinstance(reports, list)

    def test_get_report_content_nonexistent(self, reporter):
        result = reporter.get_report_content("nonexistent.json")
        assert result is None


class TestAutoReportService:
    @pytest.fixture
    def auto_reporter(self):
        from modules.automations.auto_report import AutoReportService
        return AutoReportService()

    def test_count_by_dict(self, auto_reporter):
        items = [{"module": "sql"}, {"module": "xss"}, {"module": "sql"}]
        counts = auto_reporter._count_by_dict(items, "module")
        assert counts == {"sql": 2, "xss": 1}

    def test_list_reports_empty(self, auto_reporter):
        reports = auto_reporter.list_reports()
        assert isinstance(reports, list)

    @pytest.mark.asyncio
    async def test_generate_report_delegates_returns_dict(self, auto_reporter):
        try:
            result = await auto_reporter.generate_report(scan_name="Test Scan")
            assert isinstance(result, dict)
            assert "report_metadata" in result
        except Exception as e:
            if "no such table" in str(e).lower():
                pytest.skip("Database tables not initialized")
            raise
