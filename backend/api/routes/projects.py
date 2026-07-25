import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from api.deps import get_db
from core.storage.models import (
    Project, Session, Request,
    MatchReplaceRule, InterceptorRule, SessionHandlingRule,
    CookieJar, Finding, FuzzJob, ScanJob, Plugin,
)

router = APIRouter(prefix="/api/projects", tags=["projects"])


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    session_id: uuid.UUID | None = None


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    session_id: uuid.UUID | None = None


class ProjectResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    session_id: uuid.UUID | None
    created_at: str
    updated_at: str
    project_data: dict

    model_config = {"from_attributes": True}


@router.get("", response_model=list[ProjectResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    items = []
    for p in result.scalars().all():
        items.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "session_id": p.session_id,
            "created_at": p.created_at.isoformat() if p.created_at else "",
            "updated_at": p.updated_at.isoformat() if p.updated_at else "",
            "project_data": p.project_data,
        })
    return items


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(body: ProjectCreate, db: AsyncSession = Depends(get_db)):
    session_id = body.session_id
    if not session_id:
        session = Session(name=f"{body.name} Session")
        db.add(session)
        await db.flush()
        session_id = session.id

    project = Project(
        name=body.name,
        description=body.description,
        session_id=session_id,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "session_id": project.session_id,
        "created_at": project.created_at.isoformat() if project.created_at else "",
        "updated_at": project.updated_at.isoformat() if project.updated_at else "",
        "project_data": project.project_data,
    }


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: uuid.UUID, body: ProjectUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, detail="Project not found")

    for key, value in body.model_dump(exclude_none=True).items():
        setattr(project, key, value)
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(project)

    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "session_id": project.session_id,
        "created_at": project.created_at.isoformat() if project.created_at else "",
        "updated_at": project.updated_at.isoformat() if project.updated_at else "",
        "project_data": project.project_data,
    }


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, detail="Project not found")
    await db.delete(project)
    await db.commit()


async def _export_session_data(db: AsyncSession, session_id: uuid.UUID) -> dict:
    data = {"session_id": str(session_id)}

    sess = await db.get(Session, session_id)
    if sess:
        data["session"] = {
            "name": sess.name,
            "scope": sess.scope,
            "notes": sess.notes,
        }

    req_result = await db.execute(
        select(Request).where(Request.session_id == session_id).order_by(Request.timestamp)
    )
    data["requests"] = [
        {
            "id": str(r.id),
            "method": r.method,
            "url": r.url,
            "host": r.host,
            "path": r.path,
            "http_version": r.http_version,
            "request_headers": r.request_headers,
            "request_body": r.request_body,
            "response_status": r.response_status,
            "response_reason": r.response_reason,
            "response_headers": r.response_headers,
            "response_body": r.response_body,
            "response_time_ms": r.response_time_ms,
            "is_flagged": r.is_flagged,
            "tags": r.tags,
            "notes": r.notes,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in req_result.scalars().all()
    ]

    finding_result = await db.execute(
        select(Finding).where(Finding.session_id == session_id)
    )
    data["findings"] = [
        {
            "id": str(f.id),
            "module": f.module,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cwe": f.cwe,
            "cvss_score": f.cvss_score,
            "request_id": str(f.request_id) if f.request_id else None,
        }
        for f in finding_result.scalars().all()
    ]

    for model_cls, key in [
        (MatchReplaceRule, "match_replace_rules"),
        (InterceptorRule, "interceptor_rules"),
        (SessionHandlingRule, "session_handling_rules"),
        (CookieJar, "cookie_jar"),
    ]:
        r = await db.execute(select(model_cls).where(model_cls.session_id == session_id))
        items = []
        for item in r.scalars().all():
            item_dict = {c.name: getattr(item, c.name) for c in item.__table__.columns}
            for col in ("id", "session_id", "created_at", "updated_at"):
                val = item_dict.get(col)
                if isinstance(val, uuid.UUID):
                    item_dict[col] = str(val)
                elif isinstance(val, datetime):
                    item_dict[col] = val.isoformat() if val else None
            items.append(item_dict)
        data[key] = items

    return data


@router.post("/{project_id}/export")
async def export_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, detail="Project not found")

    export_data = {
        "nyx_version": "1.0.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "project": {
            "name": project.name,
            "description": project.description,
            "project_data": project.project_data,
        },
    }

    if project.session_id:
        export_data["session_data"] = await _export_session_data(db, project.session_id)

    return export_data


@router.post("/import")
async def import_project(body: dict, db: AsyncSession = Depends(get_db)):
    project_data = body.get("project", {})
    session_data = body.get("session_data")

    session_id = None
    if session_data:
        sess_info = session_data.get("session", {})
        session = Session(
            name=sess_info.get("name", "Imported Session"),
            scope=sess_info.get("scope", []),
            notes=sess_info.get("notes"),
        )
        db.add(session)
        await db.flush()
        session_id = session.id

        for req_data in session_data.get("requests", []):
            req = Request(
                session_id=session_id,
                method=req_data.get("method", "GET"),
                url=req_data.get("url", ""),
                host=req_data.get("host", ""),
                path=req_data.get("path", ""),
                http_version=req_data.get("http_version", "HTTP/1.1"),
                request_headers=req_data.get("request_headers", {}),
                request_body=req_data.get("request_body"),
                response_status=req_data.get("response_status"),
                response_reason=req_data.get("response_reason"),
                response_headers=req_data.get("response_headers"),
                response_body=req_data.get("response_body"),
                is_flagged=req_data.get("is_flagged", False),
                tags=req_data.get("tags", []),
                notes=req_data.get("notes"),
            )
            db.add(req)

        for finding_data in session_data.get("findings", []):
            finding = Finding(
                session_id=session_id,
                module=finding_data.get("module", ""),
                severity=finding_data.get("severity", "info"),
                title=finding_data.get("title", ""),
                description=finding_data.get("description", ""),
                evidence=finding_data.get("evidence"),
                remediation=finding_data.get("remediation"),
                cwe=finding_data.get("cwe"),
                cvss_score=finding_data.get("cvss_score"),
            )
            db.add(finding)

        for rule_data in session_data.get("match_replace_rules", []):
            rule_data.pop("id", None)
            rule_data.pop("updated_at", None)
            rule_data.pop("created_at", None)
            rule = MatchReplaceRule(session_id=session_id, **rule_data)
            db.add(rule)

        for rule_data in session_data.get("interceptor_rules", []):
            rule_data.pop("id", None)
            rule_data.pop("updated_at", None)
            rule_data.pop("created_at", None)
            rule = InterceptorRule(session_id=session_id, **rule_data)
            db.add(rule)

        for rule_data in session_data.get("session_handling_rules", []):
            rule_data.pop("id", None)
            rule_data.pop("updated_at", None)
            rule_data.pop("created_at", None)
            rule = SessionHandlingRule(session_id=session_id, **rule_data)
            db.add(rule)

        for cookie_data in session_data.get("cookie_jar", []):
            cookie_data.pop("id", None)
            cookie_data.pop("created_at", None)
            cookie = CookieJar(session_id=session_id, **cookie_data)
            db.add(cookie)

    project = Project(
        name=project_data.get("name", "Imported Project"),
        description=project_data.get("description"),
        session_id=session_id,
        project_data=project_data.get("project_data", {}),
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    return {
        "id": project.id,
        "name": project.name,
        "session_id": str(project.session_id) if project.session_id else None,
    }
