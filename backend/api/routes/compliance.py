"""Compliance report API — generates OWASP, PCI-DSS, GDPR reports from findings."""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_db
from modules.compliance.reporter import ComplianceReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("/owasp")
async def get_owasp_report(db: AsyncSession = Depends(get_db)):
    """Generate an OWASP Top 10 2021 compliance report.

    Maps all findings in the current database to the 10 OWASP categories
    and reports which categories have violations and which are clean.
    """
    gen = ComplianceReportGenerator(db)
    report = await gen.generate_owasp_report()
    logger.info(
        "OWASP report generated: %d findings across %d/%d categories",
        report["summary"]["total_findings"],
        report["summary"]["categories_with_findings"],
        10,
    )
    return report


@router.get("/pci-dss")
async def get_pci_dss_report(db: AsyncSession = Depends(get_db)):
    """Generate a PCI-DSS v4.0 compliance report.

    Maps findings to PCI-DSS requirements 6.x, 8.x, 10.x, 11.x, 12.x
    and reports pass/fail status per requirement.
    """
    gen = ComplianceReportGenerator(db)
    return await gen.generate_pci_dss_report()


@router.get("/gdpr")
async def get_gdpr_report(db: AsyncSession = Depends(get_db)):
    """Generate a GDPR Art. 32 compliance report.

    Evaluates findings against GDPR Article 32 (security of processing):
    encryption, integrity, confidentiality, resilience, and regular testing.
    """
    gen = ComplianceReportGenerator(db)
    return await gen.generate_gdpr_report()


@router.get("/full")
async def get_full_compliance_report(db: AsyncSession = Depends(get_db)):
    """Generate all compliance reports in a single response.

    Includes OWASP Top 10, PCI-DSS v4.0, and GDPR Art. 32 — useful for
    generating a comprehensive compliance snapshot in one API call.
    """
    gen = ComplianceReportGenerator(db)
    return await gen.generate_full_report()


@router.get("/status")
async def compliance_status(db: AsyncSession = Depends(get_db)):
    """Quick compliance overview without full report generation.

    Returns the counts needed for a dashboard widget: total findings,
    OWASP categories with violations, and PCI-DSS pass/fail ratio.
    """
    gen = ComplianceReportGenerator(db)
    owasp = await gen.generate_owasp_report()
    pci = await gen.generate_pci_dss_report()
    return {
        "total_findings": owasp["summary"]["total_findings"],
        "owasp_categories_with_findings": owasp["summary"]["categories_with_findings"],
        "owasp_categories_clean": owasp["summary"]["categories_clean"],
        "pci_requirements_passed": pci["summary"]["passed"],
        "pci_requirements_failed": pci["summary"]["failed"],
        "overall_risk": "HIGH" if pci["summary"]["failed"] > 0 else "LOW",
    }