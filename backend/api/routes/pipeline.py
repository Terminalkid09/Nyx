from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from modules.pipeline.orchestrator import ScanPipeline

router = APIRouter(prefix="/api/pipeline", tags=["pipeline"])


class StartPipelineRequest(BaseModel):
    target_url: str
    session_id: str | None = None
    config: dict = {}


def get_pipeline(request: Request) -> ScanPipeline:
    if not hasattr(request.app.state, 'pipeline_service'):
        request.app.state.pipeline_service = ScanPipeline(request.app.state.event_bus)
    return request.app.state.pipeline_service


@router.post("/start")
async def start_pipeline(body: StartPipelineRequest, request: Request):
    pipeline = get_pipeline(request)
    result = await pipeline.start_pipeline(
        target_url=body.target_url,
        session_id=body.session_id or "",
        config=body.config,
    )
    return result


@router.get("/{pipeline_id}")
async def get_pipeline_status(pipeline_id: str, request: Request):
    pipeline = get_pipeline(request)
    result = pipeline.get_pipeline(pipeline_id)
    if not result:
        raise HTTPException(404, detail="Pipeline not found")
    return result


@router.get("")
async def list_pipelines(request: Request):
    pipeline = get_pipeline(request)
    return pipeline.list_pipelines()


@router.post("/{pipeline_id}/cancel")
async def cancel_pipeline(pipeline_id: str, request: Request):
    pipeline = get_pipeline(request)
    existing = pipeline.get_pipeline(pipeline_id)
    if not existing:
        raise HTTPException(404, detail="Pipeline not found")
    pipeline.cancel_pipeline(pipeline_id)
    return {"detail": "Pipeline cancelled", "pipeline_id": pipeline_id}
