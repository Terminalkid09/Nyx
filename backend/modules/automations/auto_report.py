import logging

logger = logging.getLogger(__name__)


class AutoReportService:
    """Thin wrapper around ReporterService for backwards compatibility.

    ``session_id`` is *required* — reports are always scoped to one session.
    Passing ``None`` previously merged data from all sessions into a single
    report without the caller being aware, mixing unrelated sessions.
    """

    async def generate_report(self, session_id: str, scan_name: str = "Nyx Scan Report") -> dict:
        if not session_id:
            raise ValueError("session_id is required for a report generation")
        from reporter.service import ReporterService
        svc = ReporterService()
        report_bytes = await svc.generate_from_db(session_id=session_id, format="json")
        import json
        report = json.loads(report_bytes)
        report["report_metadata"] = {
            "title": scan_name,
            "generated_at": report.get("generated_at"),
            "tool": "Nyx Security Suite",
            "version": "1.0.0",
            "session_id": session_id,
        }
        report["statistics"] = {
            "findings_by_module": self._count_by_dict(report.get("findings", []), "module"),
            "findings_by_severity": report.get("by_severity", {}),
        }
        return report

    async def save_report(self, session_id: str, scan_name: str = "Nyx Scan Report") -> dict:
        if not session_id:
            raise ValueError("session_id is required for a report save")
        from reporter.service import ReporterService
        svc = ReporterService()
        return await svc.save_report(session_id=session_id, scan_name=scan_name)

    def _count_by_dict(self, items: list[dict], field: str) -> dict:
        counts = {}
        for item in items:
            val = str(item.get(field, "unknown"))
            counts[val] = counts.get(val, 0) + 1
        return counts

    def list_reports(self) -> list[dict]:
        from reporter.service import ReporterService
        svc = ReporterService()
        return svc.list_reports()

    def get_report_content(self, filename: str) -> dict | None:
        from reporter.service import ReporterService
        svc = ReporterService()
        return svc.get_report_content(filename)
