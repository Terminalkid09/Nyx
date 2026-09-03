"""Durably store scanner results and announce them to the UI/automations."""
import uuid

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import Finding, SeverityEnum
from core.storage.traffic import DEFAULT_SESSION_ID


async def persist_results(event_bus: EventBus, results: list, event: dict, module: str, source: str = "passive"):
    """Persist scanner results and publish ``finding.created`` events.

    ``source`` marks the scan family that produced the finding ("passive" or
    "active") so consumers (live audit stats, triage) can route them without
    guessing from check names.
    """
    try:
        session_id = uuid.UUID(str(event.get("session_id") or DEFAULT_SESSION_ID))
    except ValueError:
        session_id = DEFAULT_SESSION_ID
    try:
        request_id = uuid.UUID(str(event.get("request_id"))) if event.get("request_id") else None
    except ValueError:
        request_id = None
    async with AsyncSessionLocal() as db:
        for result in results:
            if not result.triggered:
                continue
            severity = SeverityEnum(str(result.severity).lower())
            finding = Finding(
                session_id=session_id, request_id=request_id, module=module,
                severity=severity, title=result.title, description=result.description,
                evidence=result.evidence, remediation=result.remediation, cwe=result.cwe,
                cvss_score=getattr(result, 'cvss_score', None),
                cvss_vector=getattr(result, 'cvss_vector', None)
            )
            db.add(finding)
            await db.flush()
            await event_bus.publish({"type": "finding.created", "id": str(finding.id),
                "session_id": str(session_id), "request_id": str(request_id) if request_id else None,
                "module": module, "source": source, "severity": severity.value, "title": finding.title,
                "description": finding.description, "evidence": finding.evidence,
                "cwe": finding.cwe, "cvss_score": finding.cvss_score, "cvss_vector": finding.cvss_vector})
        await db.commit()
