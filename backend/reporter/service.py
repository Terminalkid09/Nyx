import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from jinja2 import Environment, FileSystemLoader, select_autoescape
import uuid

logger = logging.getLogger(__name__)


class ReporterService:
    def __init__(self):
        template_dir = Path(__file__).parent / "templates"
        self.reports_dir = Path(__file__).parent.parent / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            # Auto-escape HTML templates so attacker-controlled finding content
            # (evidence bodies, headers, titles) can't inject markup or scripts
            # into generated reports. Markdown keeps raw text for formatting.
            autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml")),
        )

    async def generate(
        self,
        session_id: uuid.UUID,
        findings: list[dict],
        request_count: int,
        format: str = "html",
        target_url: str | None = None,
    ) -> bytes:
        by_severity = dict(Counter(f.get("severity", "info") for f in findings))
        severity_order = ["critical", "high", "medium", "low", "info"]

        context = {
            "session_id": str(session_id),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "target_url": target_url,
            "findings": sorted(
                findings,
                key=lambda f: severity_order.index(f.get("severity", "info")) if f.get("severity") in severity_order else 99,
            ),
            "by_severity": by_severity,
            "by_severity_items": sorted(by_severity.items(), key=lambda x: severity_order.index(x[0]) if x[0] in severity_order else 99),
            "total_findings": len(findings),
            "request_count": request_count,
        }

        if format == "json":
            return json.dumps(context, indent=2, default=str).encode()

        if format == "md":
            template = self.env.get_template("report.md")
            return template.render(**context).encode()

        if format == "html":
            template = self.env.get_template("report.html")
            return template.render(**context).encode()

        if format == "pdf":
            template = self.env.get_template("report.html")
            html = template.render(**context)
            try:
                from weasyprint import HTML as WeasyprintHTML
                return WeasyprintHTML(string=html).write_pdf()
            except ImportError:
                logger.warning("weasyprint not installed, falling back to HTML")
                return html.encode()

        raise ValueError(f"Unknown format: {format}")

    async def generate_from_db(
        self,
        session_id: str,
        format: str = "json",
    ) -> bytes:
        """Generate a report for one concrete ``session_id``.

        The session is required: omitting it used to silently aggregate
        findings across every session, mixing unrelated scopes. Callers must
        pass an explicit session (or intentionally decide on an aggregate
        report elsewhere).
        """
        if not session_id:
            raise ValueError("session_id is required to generate a report — pass a concrete session UUID")
        try:
            session_uuid = uuid.UUID(str(session_id))
        except (ValueError, AttributeError):
            raise ValueError(f"Invalid session_id: {session_id!r}")
        from core.storage.database import AsyncSessionLocal
        from core.storage.models import Finding, Request
        from sqlalchemy import select, func

        async with AsyncSessionLocal() as db:
            findings_query = select(Finding).where(Finding.session_id == session_uuid)
            findings_query = findings_query.order_by(Finding.severity.desc())
            result = await db.execute(findings_query)
            findings = list(result.scalars().all())

            count_query = select(func.count(Request.id)).where(Request.session_id == session_uuid)
            req_result = await db.execute(count_query)
            request_count = req_result.scalar() or 0

        findings_dicts = [
            {
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cwe": f.cwe,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "module": f.module,
                "id": str(f.id),
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ]

        report_session_id = session_uuid
        return await self.generate(
            session_id=report_session_id,
            findings=findings_dicts,
            request_count=request_count,
            format=format,
        )

    async def save_report(self, session_id: str, scan_name: str = "Nyx Scan Report") -> dict:
        json_bytes = await self.generate_from_db(session_id=session_id, format="json")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.json"
        filepath = self.reports_dir / filename
        filepath.write_text(json_bytes.decode())
        report_data = json.loads(json_bytes)
        report_data["saved_to"] = str(filepath)
        return report_data

    def list_reports(self) -> list[dict]:
        if not self.reports_dir.exists():
            return []
        reports = []
        for f in sorted(self.reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if f.suffix in (".json", ".html", ".md"):
                reports.append({
                    "filename": f.name,
                    "path": str(f),
                    "size": f.stat().st_size,
                    "created_at": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
                })
        return reports

    def get_report_content(self, filename: str) -> dict | None:
        filepath = self.reports_dir / filename
        if not filepath.exists() or filepath.suffix not in (".json", ".html", ".md"):
            return None
        try:
            if filepath.suffix == ".json":
                return json.loads(filepath.read_text())
            return {"content": filepath.read_text(), "format": filepath.suffix.lstrip(".")}
        except Exception:
            return None
