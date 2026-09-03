"""Compliance report generator tests."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestComplianceReporter:
    """Test the compliance report generator with mock findings."""

    def _mock_findings(self):
        """Create mock findings for testing."""
        findings = [
            MagicMock(id="f1", title="SQL Injection in login", severity=MagicMock(value="high"),
                      cwe="CWE-89", description="SQL injection", host="app.example.com", path="/login",
                      cvss_score=8.5),
            MagicMock(id="f2", title="XSS in search", severity=MagicMock(value="medium"),
                      cwe="CWE-79", description="Cross-site scripting", host="app.example.com", path="/search",
                      cvss_score=6.0),
            MagicMock(id="f3", title="Missing CSP header", severity=MagicMock(value="low"),
                      cwe=None, description="Content Security Policy missing", host="app.example.com", path="/",
                      cvss_score=3.0),
            MagicMock(id="f4", title="CORS misconfiguration", severity=MagicMock(value="high"),
                      cwe=None, description="Access-Control-Allow-Origin: *", host="api.example.com", path="/",
                      cvss_score=7.0),
            MagicMock(id="f5", title="SSRF via webhook URL", severity=MagicMock(value="critical"),
                      cwe="CWE-918", description="Server-side request forgery", host="api.example.com", path="/webhook",
                      cvss_score=9.5),
        ]
        return findings

    def test_owasp_mapping_injection(self):
        from modules.compliance.reporter import ComplianceReportGenerator, OWASP_TOP10_2021

        gen = ComplianceReportGenerator.__new__(ComplianceReportGenerator)
        findings = [
            {"id": "f1", "title": "SQL Injection", "severity": "high", "cwe": "CWE-89",
             "description": "SQL injection in login", "host": "", "path": "", "cvss_score": 8.5},
            {"id": "f2", "title": "XSS", "severity": "medium", "cwe": "CWE-79",
             "description": "Cross-site scripting", "host": "", "path": "", "cvss_score": 6.0},
        ]
        mapped = gen._findings_to_owasp(findings)
        assert len(mapped["A03:2021"]) == 2, "Both SQLi and XSS should map to A03:2021 Injection"

    def test_owasp_mapping_ssrf(self):
        from modules.compliance.reporter import ComplianceReportGenerator

        gen = ComplianceReportGenerator.__new__(ComplianceReportGenerator)
        findings = [
            {"id": "f1", "title": "SSRF via webhook", "severity": "critical", "cwe": "CWE-918",
             "description": "Server-side request forgery", "host": "", "path": "", "cvss_score": 9.5},
        ]
        mapped = gen._findings_to_owasp(findings)
        assert len(mapped["A10:2021"]) == 1, "SSRF should map to A10:2021 SSRF"

    def test_owasp_mapping_cors(self):
        from modules.compliance.reporter import ComplianceReportGenerator

        gen = ComplianceReportGenerator.__new__(ComplianceReportGenerator)
        findings = [
            {"id": "f1", "title": "CORS misconfiguration", "severity": "high", "cwe": None,
             "description": "Access-Control-Allow-Origin: *", "host": "", "path": "", "cvss_score": 7.0},
        ]
        mapped = gen._findings_to_owasp(findings)
        assert len(mapped["A05:2021"]) == 1, "CORS misconfig should map to A05:2021 Security Misconfiguration"

    def test_owasp_empty_findings(self):
        from modules.compliance.reporter import ComplianceReportGenerator

        gen = ComplianceReportGenerator.__new__(ComplianceReportGenerator)
        mapped = gen._findings_to_owasp([])
        for k, v in mapped.items():
            assert len(v) == 0, f"Empty findings should produce empty category for {k}"

    @pytest.mark.asyncio
    async def test_pci_dss_report_structure(self):
        from modules.compliance.reporter import ComplianceReportGenerator

        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        gen = ComplianceReportGenerator(db)
        report = await gen.generate_pci_dss_report()

        assert "report_id" in report
        assert "pci_dss" in report.get("framework", "").lower() or "PCI" in report.get("framework", "")
        assert "requirements" in report
        assert report["summary"]["total_requirements"] > 0
        # Empty findings should mean all requirements PASS
        assert report["summary"]["failed"] == 0
        assert report["summary"]["passed"] == report["summary"]["total_requirements"]

    @pytest.mark.asyncio
    async def test_gdpr_report_structure(self):
        from modules.compliance.reporter import ComplianceReportGenerator

        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        gen = ComplianceReportGenerator(db)
        report = await gen.generate_gdpr_report()

        assert "report_id" in report
        assert "articles" in report
        assert report["summary"]["total_articles"] > 0

    @pytest.mark.asyncio
    async def test_full_report_includes_all_frameworks(self):
        from modules.compliance.reporter import ComplianceReportGenerator

        db = AsyncMock()
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute = AsyncMock(return_value=result_mock)

        gen = ComplianceReportGenerator(db)
        report = await gen.generate_full_report()

        assert "owasp" in report
        assert "pci_dss" in report
        assert "gdpr" in report
        assert "findings_total" in report


class TestComplianceRoutes:
    """API route tests for compliance endpoints."""

    @pytest.mark.asyncio
    async def test_owasp_endpoint(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/compliance/owasp")

        assert resp.status_code == 200
        data = resp.json()
        assert "categories" in data
        assert len(data["categories"]) == 10  # OWASP Top 10 has 10 categories

    @pytest.mark.asyncio
    async def test_pci_dss_endpoint(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/compliance/pci-dss")

        assert resp.status_code == 200
        data = resp.json()
        assert "requirements" in data
        assert "summary" in data

    @pytest.mark.asyncio
    async def test_gdpr_endpoint(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/compliance/gdpr")

        assert resp.status_code == 200
        data = resp.json()
        assert "articles" in data

    @pytest.mark.asyncio
    async def test_full_compliance_endpoint(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/compliance/full")

        assert resp.status_code == 200
        data = resp.json()
        assert "owasp" in data
        assert "pci_dss" in data
        assert "gdpr" in data

    @pytest.mark.asyncio
    async def test_compliance_status_endpoint(self):
        from main import app
        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/compliance/status")

        assert resp.status_code == 200
        data = resp.json()
        assert "total_findings" in data
        assert "overall_risk" in data