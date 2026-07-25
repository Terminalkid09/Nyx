from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.repeater.service import RepeaterService

router = APIRouter(prefix="/api/repeater", tags=["repeater"])

service = RepeaterService()


class RepeaterRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: str | None = None


class RepeaterResponse(BaseModel):
    status: int
    headers: dict
    body: str | None
    time_ms: int


class TabCreate(BaseModel):
    name: str = "Untitled"
    request_data: dict | None = None


class TabResponse(BaseModel):
    id: str
    name: str
    created_at: str = ""
    history_count: int = 0


class HistoryEntry(BaseModel):
    method: str
    url: str
    headers: dict
    body: str | None
    response_status: int | None
    response_headers: dict | None
    response_body: str | None
    time_ms: int | None
    timestamp: str


@router.post("/send", response_model=RepeaterResponse)
async def send_request(req: RepeaterRequest):
    tab = service.create_tab(name="Direct", request_data=req.model_dump())
    result = await service.send_request(tab.id, req.method, req.url, req.headers, req.body)
    if not result:
        raise HTTPException(500, detail="Failed to send request")
    service.close_tab(tab.id)
    return result

@router.post("/tabs/{tab_id}/send", response_model=RepeaterResponse)
async def send_tab_request(tab_id: str, req: RepeaterRequest):
    result = await service.send_request(tab_id, req.method, req.url, req.headers, req.body)
    if not result:
        raise HTTPException(500, detail="Failed to send request")
    return result


@router.get("/tabs", response_model=list[TabResponse])
async def list_tabs():
    tabs = service.get_tabs()
    return [
        TabResponse(id=t.id, name=t.name, history_count=len(t.request_history))
        for t in tabs
    ]


@router.post("/tabs", response_model=TabResponse, status_code=201)
async def create_tab(body: TabCreate):
    tab = service.create_tab(name=body.name, request_data=body.request_data)
    return TabResponse(id=tab.id, name=tab.name, history_count=len(tab.request_history))


@router.delete("/tabs/{tab_id}", status_code=204)
async def delete_tab(tab_id: str):
    if not service.close_tab(tab_id):
        raise HTTPException(404, detail="Tab not found")


@router.get("/tabs/{tab_id}", response_model=TabResponse)
async def get_tab(tab_id: str):
    tab = service.get_tab(tab_id)
    if not tab:
        raise HTTPException(404, detail="Tab not found")
    return TabResponse(id=tab.id, name=tab.name, history_count=len(tab.request_history))


@router.get("/tabs/{tab_id}/history", response_model=list[HistoryEntry])
async def get_tab_history(tab_id: str):
    tab = service.get_tab(tab_id)
    if not tab:
        raise HTTPException(404, detail="Tab not found")
    return [
        HistoryEntry(
            method=e.method,
            url=e.url,
            headers=e.headers,
            body=e.body,
            response_status=e.response_status,
            response_headers=e.response_headers,
            response_body=e.response_body,
            time_ms=e.time_ms,
            timestamp=e.timestamp,
        )
        for e in tab.request_history
    ]
