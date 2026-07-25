import uuid
from sqlalchemy import select, desc, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from core.storage.models import Request


async def create_request(db: AsyncSession, session_id: uuid.UUID, **data) -> Request:
    req = Request(session_id=session_id, **data)
    db.add(req)
    await db.commit()
    await db.refresh(req)
    return req


async def get_request(db: AsyncSession, request_id: uuid.UUID) -> Request | None:
    result = await db.execute(select(Request).where(Request.id == request_id))
    return result.scalar_one_or_none()


async def list_requests(
    db: AsyncSession,
    session_id: uuid.UUID | None = None,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    search: str | None = None,
    flagged: bool | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[Request], int]:
    query = select(Request).order_by(desc(Request.timestamp))

    if session_id is not None:
        query = query.where(Request.session_id == session_id)
    if host:
        query = query.where(Request.host.ilike(f"%{host}%"))
    if method:
        query = query.where(Request.method == method.upper())
    if status is not None:
        query = query.where(Request.response_status == status)
    if flagged is not None:
        query = query.where(Request.is_flagged == flagged)
    if search:
        query = query.where(Request.url.ilike(f"%{search}%"))

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * per_page
    result = await db.execute(query.offset(offset).limit(per_page))
    items = list(result.scalars().all())

    return items, total


async def update_request(
    db: AsyncSession,
    request_id: uuid.UUID,
    **kwargs,
) -> Request | None:
    await db.execute(
        update(Request).where(Request.id == request_id).values(**kwargs)
    )
    await db.commit()
    return await get_request(db, request_id)
