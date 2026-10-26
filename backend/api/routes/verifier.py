"""F-04: differential PoC verification endpoint."""
import copy
import urllib.parse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.authorization import authorize
from modules.auto_exploit.verifier import run_verification

router = APIRouter(prefix="/api/auto-exploit", tags=["auto-exploit"])


class VerifyRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}
    body: str | None = None
    param: str | None = None
    payload: str | None = None
    session_id: str | None = None


def inject_query(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query[param] = payload
    return parsed._replace(query=urllib.parse.urlencode(query)).geturl()


@router.post("/verify")
async def verify(body: VerifyRequest):
    if body.param and body.payload is None:
        raise HTTPException(400, "payload is required when param is set")

    allowed, kind, detail = await authorize(body.session_id, body.url)
    if not allowed:
        raise HTTPException(
            403, f"Target not authorized ({kind}: {detail})"
        )

    baseline_request = {
        "method": body.method.upper(),
        "url": body.url,
        "headers": body.headers,
        "content": body.body,
    }
    injected_request = copy.deepcopy(baseline_request)
    if body.param:
        injected_request["url"] = inject_query(body.url, body.param, body.payload)
        # The injected URL is a second outbound request and can fall under a
        # different RoE exclusion (query/path patterns), so it needs its own
        # authorization decision.
        if injected_request["url"] != body.url:
            allowed, kind, detail = await authorize(
                body.session_id, injected_request["url"]
            )
            if not allowed:
                raise HTTPException(
                    403, f"Target not authorized ({kind}: {detail})"
                )

    from core.roe import pace

    await pace(body.url)
    if injected_request["url"] != body.url:
        await pace(injected_request["url"])

    try:
        verdict = await run_verification(baseline_request, injected_request)
    except Exception as exc:  # noqa: BLE001 — surface a clean 502
        raise HTTPException(502, f"Verification failed: {exc}") from exc
    return verdict.to_dict()
