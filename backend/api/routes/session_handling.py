from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from datetime import datetime, timezone
import uuid

from api.deps import get_db
from core.storage.models import SessionHandlingRule, CookieJar

router = APIRouter(prefix="/api/session", tags=["session"])


# --- Schemas ---

class RuleCreate(BaseModel):
    session_id: uuid.UUID
    name: str
    rule_type: str = "cookie_jar"
    enabled: bool = True
    config: dict = {}
    order: int = 0


class RuleUpdate(BaseModel):
    name: str | None = None
    rule_type: str | None = None
    enabled: bool | None = None
    config: dict | None = None
    order: int | None = None


class RuleResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    name: str
    rule_type: str
    enabled: bool
    config: dict
    order: int

    model_config = {"from_attributes": True}


class CookieCreate(BaseModel):
    session_id: uuid.UUID
    domain: str
    name: str
    value: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    expires: datetime | None = None


class CookieResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    domain: str
    name: str
    value: str
    path: str
    secure: bool
    http_only: bool
    same_site: str | None
    expires: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class MacroRunRequest(BaseModel):
    session_id: uuid.UUID
    requests: list[dict]


class MacroStepsUpdate(BaseModel):
    steps: list[dict]


# --- Session Handling Rules CRUD ---

@router.get("/rules", response_model=list[RuleResponse])
async def list_rules(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SessionHandlingRule).order_by(SessionHandlingRule.order))
    return list(result.scalars().all())


@router.post("/rules", response_model=RuleResponse, status_code=201)
async def create_rule(body: RuleCreate, db: AsyncSession = Depends(get_db)):
    rule = SessionHandlingRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.put("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: uuid.UUID, body: RuleUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SessionHandlingRule).where(SessionHandlingRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(rule, key, value)
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SessionHandlingRule).where(SessionHandlingRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()


# --- Cookie Jar ---

@router.get("/cookies", response_model=list[CookieResponse])
async def list_cookies(
    domain: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(CookieJar).order_by(CookieJar.domain, CookieJar.name)
    if domain:
        stmt = stmt.where(CookieJar.domain == domain)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post("/cookies", response_model=CookieResponse, status_code=201)
async def add_cookie(body: CookieCreate, db: AsyncSession = Depends(get_db)):
    cookie = CookieJar(**body.model_dump())
    db.add(cookie)
    await db.commit()
    await db.refresh(cookie)
    return cookie


@router.delete("/cookies/{cookie_id}", status_code=204)
async def delete_cookie(cookie_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CookieJar).where(CookieJar.id == cookie_id))
    cookie = result.scalar_one_or_none()
    if not cookie:
        raise HTTPException(404, detail="Cookie not found")
    await db.delete(cookie)
    await db.commit()


# --- Macro Steps Update ---

@router.put("/rules/{rule_id}/macro-steps", response_model=RuleResponse)
async def update_macro_steps(rule_id: uuid.UUID, body: MacroStepsUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SessionHandlingRule).where(SessionHandlingRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    cfg = dict(rule.config or {})
    cfg["requests"] = body.steps
    rule.config = cfg
    await db.commit()
    await db.refresh(rule)
    return rule


# --- Macro Execution ---

@router.post("/macros/run")
async def run_macro(body: MacroRunRequest, request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine or not hasattr(engine, "macro_engine"):
        raise HTTPException(503, "Macro engine not available")
    try:
        results = await engine.macro_engine.execute_macro(body.session_id, body.requests)
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    return {"results": results}


class MacroRecordRequest(BaseModel):
    session_id: uuid.UUID
    request_ids: list[uuid.UUID]


@router.post("/macros/from-requests")
async def create_macro_from_requests(body: MacroRecordRequest, db: AsyncSession = Depends(get_db)):
    from core.storage.models import Request as RequestModel
    steps = []
    for rid in body.request_ids:
        result = await db.execute(select(RequestModel).where(RequestModel.id == rid))
        req = result.scalar_one_or_none()
        if not req:
            continue
        step = {
            "method": req.method,
            "url": req.url,
            "headers": dict(req.request_headers or {}),
        }
        if req.request_body:
            step["body"] = req.request_body
        # Auto-detect CSRF tokens and other common session params in URL
        import urllib.parse
        parsed = urllib.parse.urlparse(req.url)
        qs = urllib.parse.parse_qs(parsed.query)
        csrf_params = [k for k in qs if any(x in k.lower() for x in ["csrf", "token", "nonce", "viewstate", "xsrf", "authenticity"])]
        if csrf_params:
            step["extract"] = {p: f"{p}=([^&]+)" for p in csrf_params}
        # Auto-detect CSRF in body
        if req.request_body and req.content_type and "form" in req.content_type:
            from urllib.parse import parse_qs as parse_body
            body_params = parse_body(req.request_body)
            csrf_body = [k for k in body_params if any(x in k.lower() for x in ["csrf", "token", "nonce", "xsrf", "authenticity"])]
            if csrf_body:
                if "extract" not in step:
                    step["extract"] = {}
                for p in csrf_body:
                    step["extract"][p] = f'name="{p}"[^>]*value="([^"]*)"'
        steps.append(step)
    return {"steps": steps}


# --- Session Token Detection ---

TOKEN_PATTERNS = [
    ("CSRF Token", r'name=["\']?(csrf|csrf_token|csrfmiddlewaretoken|xsrf|_csrf)["\']?\s', "Form field name"),
    ("CSRF Meta", r'<meta[^>]+name=["\']?csrf-token["\']?[^>]+content=["\']?([^"\']+)', "Meta tag"),
    ("Anti-CSRF Header", r'csrf-token[:=]\s*["\']?([^"\';\s&]+)', "Custom header"),
    ("ViewState", r'__VIEWSTATE["\']?\s*value=["\']?([^"\']+)', "ASP.NET ViewState"),
    ("ViewState Generator", r'__VIEWSTATEGENERATOR["\']?\s*value=["\']?([^"\']+)', "ASP.NET generator"),
    ("EventValidation", r'__EVENTVALIDATION["\']?\s*value=["\']?([^"\']+)', "ASP.NET validation"),
    ("Nonce (script)", r'(nonce|once)["\']?\s*[:=]\s*["\']?([a-fA-F0-9]{16,})', "Script nonce"),
    ("Bearer Token", r'["\']?access_token["\']?[:=]\s*["\']?([^"\']+)', "OAuth access token"),
    ("API Key", r'["\']?api[_-]?key["\']?[:=]\s*["\']?([^"\']+)', "API key in JSON"),
    ("Session Cookie", r'Set-Cookie:\s*(session|sid|jsessionid|phpsessid|aspsessionid|token)\s*=', "Cookie header"),
]


@router.get("/tokens")
async def detect_session_tokens(db: AsyncSession = Depends(get_db)):
    from core.storage.models import Request as RequestModel
    from sqlalchemy import select, desc

    result = await db.execute(
        select(RequestModel)
        .where(RequestModel.response_body.isnot(None))
        .order_by(desc(RequestModel.timestamp))
        .limit(50)
    )
    requests = result.scalars().all()

    tokens_found = []
    for req in requests:
        body = (req.response_body or "") + (req.request_body or "")
        headers_str = str(dict(req.response_headers or {})) + str(dict(req.request_headers or {}))
        combined = body + "\n" + headers_str
        for token_name, pattern, source in TOKEN_PATTERNS:
            import re
            matches = re.findall(pattern, combined, re.IGNORECASE)
            for m in matches[:3]:
                value = m if isinstance(m, str) else m[-1]
                if len(value) > 3 and len(value) < 200:
                    tokens_found.append({
                        "token_type": token_name,
                        "value": value[:80],
                        "source": source,
                        "request_id": str(req.id),
                        "url": req.url,
                        "method": req.method,
                    })
    # Deduplicate
    seen = set()
    unique_tokens = []
    for t in tokens_found:
        key = (t["token_type"], t["value"])
        if key not in seen:
            seen.add(key)
            unique_tokens.append(t)
    return {"tokens": unique_tokens[:50]}


class ScopeUpdate(BaseModel):
    scope_url_pattern: str = ""


@router.put("/rules/{rule_id}/scope", response_model=RuleResponse)
async def set_rule_scope(rule_id: uuid.UUID, body: ScopeUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SessionHandlingRule).where(SessionHandlingRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(404, detail="Rule not found")
    cfg = dict(rule.config or {})
    cfg["scope_url_pattern"] = body.scope_url_pattern
    rule.config = cfg
    await db.commit()
    await db.refresh(rule)
    return rule


# --- Variable Persistence ---

class VariableSaveRequest(BaseModel):
    name: str


class VariableExportResponse(BaseModel):
    variables: dict[str, str]
    count: int


@router.post("/variables/save/{name}")
async def save_variables(name: str, request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine or not hasattr(engine, "macro_engine"):
        raise HTTPException(503, "Session handling engine not available")
    result = engine.macro_engine.save_variables(name)
    return {"status": "saved", "name": name, "variables": result, "count": len(result)}


@router.post("/variables/load/{name}")
async def load_variables(name: str, request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine or not hasattr(engine, "macro_engine"):
        raise HTTPException(503, "Session handling engine not available")
    snapshot = engine.macro_engine.load_variables(name)
    if snapshot is None:
        raise HTTPException(404, detail=f"No saved variables found under '{name}'")
    return {"status": "loaded", "name": name, "variables": snapshot, "count": len(snapshot)}


@router.get("/variables")
async def list_variables(request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine or not hasattr(engine, "macro_engine"):
        raise HTTPException(503, "Session handling engine not available")
    current = engine.macro_engine.get_all_variables()
    saved = engine.macro_engine.list_saved_variables()
    return {"current_variables": current, "current_count": len(current), "saved_snapshots": saved}


@router.delete("/variables")
async def clear_variables(request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine or not hasattr(engine, "macro_engine"):
        raise HTTPException(503, "Session handling engine not available")
    engine.macro_engine.clear_variables()
    return {"status": "cleared"}


# --- Session Recording ---

class SessionRecordingStart(BaseModel):
    session_id: uuid.UUID


@router.post("/recording/start")
async def start_recording(body: SessionRecordingStart, request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine:
        raise HTTPException(503, "Session handling engine not available")
    engine._recording[str(body.session_id)] = {
        "active": True,
        "requests": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    return {"status": "started", "session_id": str(body.session_id)}


@router.post("/recording/stop")
async def stop_recording(body: SessionRecordingStart, request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine:
        raise HTTPException(503, "Session handling engine not available")
    sid = str(body.session_id)
    if sid in engine._recording:
        engine._recording[sid]["active"] = False
    return {"status": "stopped", "session_id": sid}


@router.get("/recording/{session_id}")
async def get_recording(session_id: str, request: Request = None):
    engine = request.app.state.session_handling_engine if hasattr(request.app.state, "session_handling_engine") else None
    if not engine:
        raise HTTPException(503, "Session handling engine not available")
    if not hasattr(engine, "_recording") or session_id not in engine._recording:
        return {"session_id": session_id, "active": False, "requests": [], "count": 0}
    rec = engine._recording[session_id]
    return {
        "session_id": session_id,
        "active": rec["active"],
        "started_at": rec.get("started_at", ""),
        "requests": rec["requests"],
        "count": len(rec["requests"]),
    }
