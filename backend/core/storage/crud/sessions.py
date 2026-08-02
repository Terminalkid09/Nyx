import uuid
from datetime import datetime, timezone
from sqlalchemy import select, desc, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from core.storage.models import (
    Session,
    Request,
    Finding,
    MatchReplaceRule,
    FuzzJob,
    InterceptorRule,
    SessionHandlingRule,
    CookieJar,
    ComparerItem,
    WebSocketMessage,
    ScanJob,
    ContentDiscoveryJob,
    OrganizerItem,
    TargetScopeRule,
    ClickbanditConfig,
)


async def create_session(db: AsyncSession, name: str, scope: list | None = None) -> Session:
    session = Session(name=name, scope=scope or [])
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session


async def get_session(db: AsyncSession, session_id: uuid.UUID) -> Session | None:
    result = await db.execute(select(Session).where(Session.id == session_id))
    return result.scalar_one_or_none()


async def list_sessions(db: AsyncSession) -> list[Session]:
    result = await db.execute(select(Session).order_by(desc(Session.created_at)))
    return list(result.scalars().all())


async def update_session(
    db: AsyncSession,
    session_id: uuid.UUID,
    **kwargs,
) -> Session | None:
    allowed = {"name", "scope", "notes", "is_active"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return await get_session(db, session_id)
    updates["updated_at"] = datetime.now(timezone.utc)
    await db.execute(
        update(Session).where(Session.id == session_id).values(**updates)
    )
    await db.commit()
    return await get_session(db, session_id)


async def delete_session(db: AsyncSession, session_id: uuid.UUID) -> bool:
    session = await get_session(db, session_id)
    if not session:
        return False
    await db.delete(session)
    await db.commit()
    return True


SESSION_DATA_MODELS = [
    Request,          # cascades InterceptedItem via request_id
    Finding,          # cascades CollaboratorInteraction finding_id (SET NULL)
    FuzzJob,
    ScanJob,
    ContentDiscoveryJob,
    MatchReplaceRule,
    InterceptorRule,
    SessionHandlingRule,
    CookieJar,
    ComparerItem,
    WebSocketMessage,
    OrganizerItem,
    TargetScopeRule,
    ClickbanditConfig,
]


async def reset_session_data(db: AsyncSession, session_id: uuid.UUID) -> bool:
    """Delete all per-session data (findings, requests, scans, rules...) for a session."""
    session = await get_session(db, session_id)
    if not session:
        return False
    for model in SESSION_DATA_MODELS:
        await db.execute(delete(model).where(model.session_id == session_id))
    await db.commit()
    return True
