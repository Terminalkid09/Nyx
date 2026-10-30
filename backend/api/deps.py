from fastapi import HTTPException

from core.storage.database import get_db as _get_db

get_db = _get_db


def ensure_authorized(allowed: bool, kind: str | None, detail: str | None) -> None:
    """Turn an authorization decision into the right HTTP error.

    A missing or malformed session is a client error: active endpoints require
    the engagement whose scope must be enforced. A well-formed session that
    does not cover the target is a 403, the same answer the rest of the API
    gives for an out-of-scope or out-of-RoE probe.
    """
    if allowed:
        return
    if kind in ("missing_session", "invalid_session"):
        raise HTTPException(
            status_code=400,
            detail=f"session_id is required for active probes ({kind})",
        )
    raise HTTPException(
        status_code=403, detail=f"Target not authorized ({kind}: {detail})"
    )
