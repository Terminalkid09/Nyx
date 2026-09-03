from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from core.recommender.engine import RecommendationEngine

router = APIRouter(prefix="/api/recommendations", tags=["recommendations"])

_rec_engine: RecommendationEngine | None = None


def init_recommender(engine: RecommendationEngine):
    global _rec_engine
    _rec_engine = engine


def get_engine() -> RecommendationEngine:
    if _rec_engine is None:
        raise HTTPException(503, detail="Recommendation engine not initialized")
    return _rec_engine


@router.get("")
async def list_recommendations(limit: int = 50, grouped: bool = False):
    engine = get_engine()
    if grouped:
        return {
            "grouped": engine.get_recommendations_grouped(active_only=True, limit=limit),
            "stats": engine.get_stats(),
        }
    return {
        "recommendations": engine.get_recommendations(active_only=True, limit=limit),
        "stats": engine.get_stats(),
    }


@router.get("/stats")
async def recommendation_stats():
    engine = get_engine()
    return engine.get_stats()


class DismissRequest(BaseModel):
    rec_id: str


@router.post("/dismiss")
async def dismiss_recommendation(body: DismissRequest):
    engine = get_engine()
    if engine.dismiss_recommendation(body.rec_id):
        return {"status": "dismissed"}
    raise HTTPException(404, detail="Recommendation not found")


class DismissAllRequest(BaseModel):
    finding_id: str


@router.post("/dismiss-all")
async def dismiss_all_for_finding(body: DismissAllRequest):
    engine = get_engine()
    count = engine.dismiss_all_for_finding(body.finding_id)
    return {"status": "dismissed", "count": count}


class ExecuteRequest(BaseModel):
    rec_id: str


@router.post("/execute")
async def execute_recommendation(body: ExecuteRequest):
    engine = get_engine()
    recs = engine.get_recommendations(active_only=True)
    target = None
    for r in recs:
        if r["id"] == body.rec_id:
            target = r
            break
    if not target:
        raise HTTPException(404, detail="Recommendation not found or already completed")

    engine.mark_executed(body.rec_id)

    finding = target["finding"]
    rule_id = target["rule_id"]
    url = ""
    from core.storage.database import AsyncSessionLocal
    from core.storage.models import Finding
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    try:
        import uuid as uuid_mod
        fid = uuid_mod.UUID(finding["id"])
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Finding).options(selectinload(Finding.request)).where(Finding.id == fid)
            )
            f = result.scalar_one_or_none()
            if f and f.request:
                url = f.request.url or ""
    except Exception:
        pass

    instructions = {
        "fuzz_param": {
            "redirect": "/fuzzer",
            "message": "Open Fuzzer with pre-populated params",
            "params": {
                "url": url,
                "positions": [finding.get("cwe", "")],
            },
        },
        "generate_exploit": {
            "redirect": "/auto-exploit",
            "message": "Open Auto Exploit with this finding",
            "params": {
                "cwe": finding.get("cwe", ""),
                "url": url,
            },
        },
        "active_scan_endpoint": {
            "redirect": "/active-scanner",
            "message": "Start active scan on this endpoint",
            "params": {"url": url},
        },
        "crawl_endpoint": {
            "redirect": "/crawler",
            "message": "Start crawling from this URL",
            "params": {"url": url},
        },
        "content_discovery": {
            "redirect": "/content-discovery",
            "message": "Start content discovery on this path",
            "params": {"url": url},
        },
    }

    return {
        "status": "executed",
        "action": instructions.get(rule_id, {"redirect": "/", "message": "Action completed"}),
    }
