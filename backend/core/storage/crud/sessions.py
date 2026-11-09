import uuid
from datetime import datetime, timezone
from sqlalchemy import select, desc, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from core.storage.models import (
    Base,
    Session,
    Request,
    Finding,
    MatchReplaceRule,
    FuzzJob,
    FuzzResult,
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


def _session_owned_tables() -> list:
    """Tables whose rows must disappear together with their session.

    ``db.delete(session)`` went through the ORM relationship, which tries to
    NULL ``requests.session_id`` — a NOT NULL column — so deleting a session
    that had captured traffic raised IntegrityError and answered 500. Deleting
    child rows explicitly (as SQL) is what the CASCADE constraints describe.

    Tables whose foreign key is ``ON DELETE SET NULL`` (a project outlives its
    session) are intentionally left alone.
    """
    owned = []
    for table in Base.metadata.tables.values():
        column = table.c.get("session_id")
        if column is None or table.name == "sessions":
            continue
        set_null = any(
            (fk.ondelete or "").upper() == "SET NULL" for fk in column.foreign_keys
        )
        if not set_null:
            owned.append(table)
    return owned


async def _delete_fuzz_results_for_session(db: AsyncSession, session_id: uuid.UUID) -> None:
    """Drop the session's fuzz results before their jobs.

    ``fuzz_results`` has no ``session_id`` column (it points at the job), so the
    generic per-session delete below cannot see it, and the ON DELETE CASCADE
    only fires when SQLite's ``foreign_keys`` pragma is on for that connection.
    """
    job_ids = select(FuzzJob.id).where(FuzzJob.session_id == session_id)
    await db.execute(delete(FuzzResult).where(FuzzResult.job_id.in_(job_ids)))


async def delete_session(db: AsyncSession, session_id: uuid.UUID) -> bool:
    session = await get_session(db, session_id)
    if not session:
        return False
    await _delete_fuzz_results_for_session(db, session_id)
    for table in _session_owned_tables():
        await db.execute(delete(table).where(table.c.session_id == session_id))
    await db.execute(delete(Session).where(Session.id == session_id))
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
    await _delete_fuzz_results_for_session(db, session_id)
    for model in SESSION_DATA_MODELS:
        await db.execute(delete(model).where(model.session_id == session_id))
    await db.commit()
    return True
