"""NIS2 Art. 21(2) and ISO/IEC 27001 Annex A compliance reports."""
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from core.storage.models import Finding, SeverityEnum
from main import app
from modules.compliance.reporter import (
    ISO_27001_CONTROLS,
    NIS2_MEASURES,
    ComplianceReportGenerator,
)


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class FakeDB:
    """Stands in for AsyncSession: the generator only calls execute()."""

    def __init__(self, findings):
        self.findings = findings

    async def execute(self, *args, **kwargs):
        return _Result(self.findings)


def finding(title, cwe=None, severity=SeverityEnum.HIGH, description=""):
    return Finding(
        session_id=uuid.uuid4(),
        module="test",
        severity=severity,
        title=title,
        description=description or title,
        cwe=cwe,
    )


def _by_id(report, key):
    return {entry[key]: entry for entry in report["measures" if key == "measure_id" else "controls"]}


@pytest.mark.asyncio
async def test_nis2_maps_findings_to_the_measures_they_evidence():
    db = FakeDB(
        [
            finding("SQL injection in /login", cwe="CWE-89"),
            finding("Password stored in cleartext", cwe="CWE-312"),
        ]
    )
    report = await ComplianceReportGenerator(db).generate_nis2_report()

    assert report["framework"] == "NIS2 Art. 21(2)"
    assert len(report["measures"]) == len(NIS2_MEASURES) == 10
    measures = _by_id(report, "measure_id")

    # Injection + vulnerable development → "security in development" measure.
    assert measures["21.2.e"]["status"] == "FAIL"
    assert measures["21.2.e"]["violation_count"] == 1
    # Cleartext secrets → the cryptography measure.
    assert measures["21.2.h"]["status"] == "FAIL"

    assert report["summary"]["failed"] == 2
    assert report["summary"]["total_violations"] == 2


@pytest.mark.asyncio
async def test_nis2_reports_governance_measures_as_not_assessed():
    report = await ComplianceReportGenerator(FakeDB([])).generate_nis2_report()

    assert report["summary"]["failed"] == 0
    assert report["summary"]["not_assessed"] == 4
    assert report["summary"]["passed"] == 6

    measures = _by_id(report, "measure_id")
    # No findings can prove a risk-analysis policy exists: never a PASS.
    assert measures["21.2.a"]["status"] == "NOT_ASSESSED"
    assert measures["21.2.b"]["status"] == "PASS"
    assert "NOT_ASSESSED" in report["scope"]["caveat"]


@pytest.mark.asyncio
async def test_iso27001_maps_controls_and_flags_access_control():
    db = FakeDB(
        [
            finding("IDOR on /api/items/{id}", cwe="CWE-639"),
            finding("SQL injection in /search", cwe="CWE-89"),
        ]
    )
    report = await ComplianceReportGenerator(db).generate_iso27001_report()

    assert report["framework"].startswith("ISO/IEC 27001:2022")
    assert len(report["controls"]) == len(ISO_27001_CONTROLS)
    controls = _by_id(report, "control_id")

    assert controls["5.15"]["status"] == "FAIL"      # access control
    assert controls["5.15"]["violation_count"] == 1
    assert controls["8.26"]["status"] == "FAIL"      # application security requirements
    assert controls["8.28"]["status"] == "FAIL"      # secure coding
    assert controls["5.7"]["status"] == "NOT_ASSESSED"  # threat intelligence
    # Cryptography stays clean when no crypto finding was reported.
    assert controls["8.24"]["status"] == "PASS"


@pytest.mark.asyncio
async def test_iso27001_scope_is_honest_about_the_auditor():
    report = await ComplianceReportGenerator(FakeDB([])).generate_iso27001_report()
    assert "auditor" in report["scope"]["caveat"]
    assert report["summary"]["total"] == len(ISO_27001_CONTROLS)


@pytest.mark.asyncio
async def test_full_report_includes_the_new_frameworks():
    report = await ComplianceReportGenerator(FakeDB([])).generate_full_report()
    assert {"owasp", "pci_dss", "gdpr", "nis2", "iso27001"} <= set(report)


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_nis2_endpoint(client):
    async with client as c:
        response = await c.get("/api/compliance/nis2")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["framework"] == "NIS2 Art. 21(2)"
    assert len(payload["measures"]) == 10
    assert "summary" in payload


@pytest.mark.asyncio
async def test_iso27001_endpoint(client):
    async with client as c:
        response = await c.get("/api/compliance/iso27001")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["framework"].startswith("ISO/IEC 27001")
    assert payload["controls"]
    assert payload["summary"]["total"] == len(payload["controls"])


@pytest.mark.asyncio
async def test_full_endpoint_carries_both_frameworks(client):
    async with client as c:
        response = await c.get("/api/compliance/full")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["nis2"]["framework"] == "NIS2 Art. 21(2)"
    assert payload["iso27001"]["framework"].startswith("ISO/IEC 27001")
