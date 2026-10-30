"""Durably store scanner results and announce them to the UI/automations."""
import uuid
from urllib.parse import urlsplit

from sqlalchemy import select

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.evidence import build_evidence, request_fields
from core.storage.models import Finding, Request, SeverityEnum
from core.storage.traffic import DEFAULT_SESSION_ID


def _response_status(event: dict) -> int | None:
    for key in ("response_status", "status_code", "status"):
        value = event.get(key)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


async def _link_request(db, session_id: uuid.UUID, event: dict) -> uuid.UUID | None:
    """Return a Request id for a finding, creating one when the event has none.

    Findings produced by active scans, content discovery and custom-URL scans
    are not tied to a captured proxy request. Retest re-sends the associated
    request, so without a row it used to fail with "Associated request not
    found". The synthetic row keeps the evidence reproducible and is keyed by
    (session, method, url) so repeated checks for the same endpoint reuse it.
    """
    method, url, headers, body = request_fields(event)
    if not url or not str(url).startswith(("http://", "https://")):
        return None
    method = (method or "GET")[:16].upper()
    split = urlsplit(str(url))
    if not split.hostname:
        return None

    existing = await db.execute(
        select(Request.id)
        .where(
            Request.session_id == session_id,
            Request.method == method,
            Request.url == str(url),
        )
        .limit(1)
    )
    existing_id = existing.scalar_one_or_none()
    if existing_id:
        return existing_id

    request_id = uuid.uuid5(
        uuid.NAMESPACE_URL, f"nyx-finding|{session_id}|{method}|{url}"
    )
    if await db.get(Request, request_id):
        return request_id

    db.add(
        Request(
            id=request_id,
            session_id=session_id,
            method=method,
            url=str(url),
            host=(event.get("host") or split.hostname or "")[:512],
            path=event.get("path") or split.path or "/",
            request_headers=headers or {},
            request_body=body if isinstance(body, str) or body is None else str(body),
            response_status=_response_status(event),
        )
    )
    await db.flush()
    return request_id


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
        if request_id is None:
            request_id = await _link_request(db, session_id, event)
        # Stage every finding first, commit once, and only then announce them.
        # Publishing before the commit let subscribers (live-audit stats, the UI,
        # automations) read a finding_id that a concurrent rollback would erase.
        created: list[dict] = []
        for result in results:
            if not result.triggered:
                continue
            severity = SeverityEnum(str(result.severity).lower())
            finding = Finding(
                session_id=session_id, request_id=request_id, module=module,
                severity=severity, title=result.title, description=result.description,
                evidence=build_evidence(result, event), remediation=result.remediation, cwe=result.cwe,
                cvss_score=getattr(result, 'cvss_score', None),
                cvss_vector=getattr(result, 'cvss_vector', None)
            )
            db.add(finding)
            await db.flush()
            # Snapshot the columns before commit: expire_on_commit would make
            # every attribute access below a lazy load.
            created.append({
                "id": str(finding.id), "session_id": str(session_id),
                "request_id": str(request_id) if request_id else None,
                "module": module, "source": source, "severity": severity.value,
                "title": finding.title, "description": finding.description,
                "evidence": finding.evidence, "cwe": finding.cwe,
                "cvss_score": finding.cvss_score, "cvss_vector": finding.cvss_vector,
            })
        await db.commit()

    for payload in created:
        await event_bus.publish({"type": "finding.created", **payload})
