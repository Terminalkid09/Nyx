import asyncio
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from core.storage.database import AsyncSessionLocal
from core.storage.models import Request as RequestModel
from sqlalchemy import select

router = APIRouter(prefix="/api/automations", tags=["automations"])


# ─── CSRF PoC ───────────────────────────────────────────────────────────────

class CsrfPocRequest(BaseModel):
    method: str = "POST"
    url: str
    headers: dict = {}
    body: str = ""
    form_data: dict | None = None


@router.post("/csrf-poc/generate")
async def generate_csrf_poc(body: CsrfPocRequest, request: Request):
    event_bus = getattr(request.app.state, 'event_bus', None)
    if not event_bus:
        raise HTTPException(503, detail="Backend not fully initialized")
    from modules.automations.csrf_poc import CsrfPocService
    service = CsrfPocService(event_bus)
    html = service.generate_poc(body.model_dump(), body.form_data)
    return {"html": html}


@router.post("/csrf-poc/generate-from-request/{request_id}")
async def generate_csrf_poc_from_request(request_id: uuid.UUID, request: Request, form_data: dict | None = None):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(RequestModel).where(RequestModel.id == request_id))
        req = result.scalar_one_or_none()
        if not req:
            raise HTTPException(404, detail="Request not found")
        req_dict = {
            "method": req.method,
            "url": req.url,
            "headers": req.request_headers or {},
            "body": req.request_body or "",
        }
    event_bus = getattr(request.app.state, 'event_bus', None)
    if not event_bus:
        raise HTTPException(503, detail="Backend not fully initialized")
    from modules.automations.csrf_poc import CsrfPocService
    service = CsrfPocService(event_bus)
    html = service.generate_poc(req_dict, form_data)
    return {"html": html}


# ─── Param Discovery ────────────────────────────────────────────────────────

class ParamDiscoveryRequest(BaseModel):
    target_url: str


class ParamChainRequest(BaseModel):
    target_url: str
    discovered_params: list[str]


@router.post("/param-discovery/start")
async def start_param_discovery(body: ParamDiscoveryRequest, request: Request):
    event_bus = getattr(request.app.state, 'event_bus', None)
    if not event_bus:
        raise HTTPException(503, detail="Backend not fully initialized")
    from modules.automations.param_chain import ParamDiscoveryService
    service = ParamDiscoveryService(event_bus)
    result = await service.discover(body.target_url)
    return result


@router.post("/param-discovery/chain")
async def param_chain(body: ParamChainRequest, request: Request):
    event_bus = getattr(request.app.state, 'event_bus', None)
    if not event_bus:
        raise HTTPException(503, detail="Backend not fully initialized")
    await event_bus.publish({
        "type": "param_chain.ready",
        "target_url": body.target_url,
        "discovered_params": body.discovered_params,
        "suggestion": f"Fuzz these {len(body.discovered_params)} discovered params on {body.target_url}",
    })
    return {
        "message": f"Discovered {len(body.discovered_params)} parameters. Fuzz chain triggered.",
        "target_url": body.target_url,
        "params": body.discovered_params,
        "fuzz_config": {
            "url": body.target_url,
            "positions": [{"param": p, "type": "query"} for p in body.discovered_params],
            "attack_type": "sniper",
        },
    }


# ─── Webhooks ───────────────────────────────────────────────────────────────

class WebhookCreate(BaseModel):
    name: str
    type: str
    url: str
    enabled: bool = True
    events: list[str] = ["finding.created"]


class WebhookUpdate(BaseModel):
    name: str | None = None
    type: str | None = None
    url: str | None = None
    enabled: bool | None = None
    events: list[str] | None = None


@router.get("/webhooks")
async def list_webhooks(request: Request):
    service = getattr(request.app.state, 'webhook_service', None)
    if not service:
        raise HTTPException(503, detail="Webhook service not available")
    return service.get_configs()


@router.post("/webhooks", status_code=201)
async def create_webhook(body: WebhookCreate, request: Request):
    service = getattr(request.app.state, 'webhook_service', None)
    if not service:
        raise HTTPException(503, detail="Webhook service not available")
    return service.add_config(body.model_dump())


@router.put("/webhooks/{config_id}")
async def update_webhook(config_id: str, body: WebhookUpdate, request: Request):
    service = getattr(request.app.state, 'webhook_service', None)
    if not service:
        raise HTTPException(503, detail="Webhook service not available")
    result = service.update_config(config_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(404, detail="Webhook config not found")
    return result


@router.delete("/webhooks/{config_id}")
async def delete_webhook(config_id: str, request: Request):
    service = getattr(request.app.state, 'webhook_service', None)
    if not service:
        raise HTTPException(503, detail="Webhook service not available")
    service.delete_config(config_id)
    return {"ok": True}


@router.post("/webhooks/test/{config_id}")
async def test_webhook(config_id: str, request: Request):
    service = getattr(request.app.state, 'webhook_service', None)
    if not service:
        raise HTTPException(503, detail="Webhook service not available")
    config = next((c for c in service.get_configs() if c.get("id") == config_id), None)
    if not config:
        raise HTTPException(404, detail="Webhook config not found")
    await service.send_alert(
        title="Nyx Test Alert",
        message="This is a test message from Nyx Security Scanner.",
        severity="info",
        fields=[{"name": "Test", "value": "OK", "short": True}],
    )
    return {"ok": True, "message": "Test alert sent"}


# ─── Scan Templates ─────────────────────────────────────────────────────────

class TemplateCreate(BaseModel):
    name: str
    description: str = ""
    config: dict = {}


class TemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    config: dict | None = None


@router.get("/templates")
async def list_templates():
    from modules.automations.scan_templates import ScanTemplateService
    service = ScanTemplateService()
    return service.list_templates()


@router.post("/templates", status_code=201)
async def create_template(body: TemplateCreate):
    from modules.automations.scan_templates import ScanTemplateService
    service = ScanTemplateService()
    return service.create_template(body.model_dump())


@router.get("/templates/{template_id}")
async def get_template(template_id: str):
    from modules.automations.scan_templates import ScanTemplateService
    service = ScanTemplateService()
    tpl = service.get_template(template_id)
    if not tpl:
        raise HTTPException(404, detail="Template not found")
    return tpl


@router.put("/templates/{template_id}")
async def update_template(template_id: str, body: TemplateUpdate):
    from modules.automations.scan_templates import ScanTemplateService
    service = ScanTemplateService()
    result = service.update_template(template_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(404, detail="Template not found")
    return result


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str):
    from modules.automations.scan_templates import ScanTemplateService
    service = ScanTemplateService()
    service.delete_template(template_id)
    return {"ok": True}


# ─── Scheduled Scans ────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    name: str
    target_url: str
    cron: str
    enabled: bool = True
    config: dict = {}
    template_id: str | None = None


class ScheduleUpdate(BaseModel):
    name: str | None = None
    target_url: str | None = None
    cron: str | None = None
    enabled: bool | None = None
    config: dict | None = None
    template_id: str | None = None


@router.get("/schedules")
async def list_schedules(request: Request):
    service = getattr(request.app.state, 'scheduled_scan_service', None)
    if not service:
        raise HTTPException(503, detail="Scheduled scan service not available")
    return service.get_schedules()


@router.post("/schedules", status_code=201)
async def create_schedule(body: ScheduleCreate, request: Request):
    service = getattr(request.app.state, 'scheduled_scan_service', None)
    if not service:
        raise HTTPException(503, detail="Scheduled scan service not available")
    return service.add_schedule(body.model_dump())


@router.put("/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, body: ScheduleUpdate, request: Request):
    service = getattr(request.app.state, 'scheduled_scan_service', None)
    if not service:
        raise HTTPException(503, detail="Scheduled scan service not available")
    result = service.update_schedule(schedule_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(404, detail="Schedule not found")
    return result


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, request: Request):
    service = getattr(request.app.state, 'scheduled_scan_service', None)
    if not service:
        raise HTTPException(503, detail="Scheduled scan service not available")
    service.delete_schedule(schedule_id)
    return {"ok": True}


@router.post("/schedules/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: str, request: Request):
    service = getattr(request.app.state, 'scheduled_scan_service', None)
    if not service:
        raise HTTPException(503, detail="Scheduled scan service not available")
    sched = next((s for s in service.get_schedules() if s.get("id") == schedule_id), None)
    if not sched:
        raise HTTPException(404, detail="Schedule not found")
    sched["enabled"] = not sched.get("enabled", True)
    service.update_schedule(schedule_id, {"enabled": sched["enabled"]})
    return {"id": schedule_id, "enabled": sched["enabled"]}


# ─── Reports ────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    session_id: uuid.UUID
    scan_name: str = "Nyx Scan Report"


@router.post("/reports/generate")
async def generate_report(body: ReportRequest):
    from modules.automations.auto_report import AutoReportService
    service = AutoReportService()
    report = await service.generate_report(body.session_id, body.scan_name)
    return report


@router.post("/reports/save")
async def save_report(body: ReportRequest):
    from modules.automations.auto_report import AutoReportService
    service = AutoReportService()
    report = await service.save_report(body.session_id, body.scan_name)
    return report


@router.get("/reports")
async def list_reports():
    from modules.automations.auto_report import AutoReportService
    service = AutoReportService()
    return service.list_reports()


@router.get("/reports/{filename}")
async def get_report(filename: str):
    from modules.automations.auto_report import AutoReportService
    service = AutoReportService()
    report = service.get_report_content(filename)
    if not report:
        raise HTTPException(404, detail="Report not found")
    return report
