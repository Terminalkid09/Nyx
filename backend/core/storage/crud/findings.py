import uuid
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from core.storage.models import Finding


async def create_finding(db: AsyncSession, **data) -> Finding:
    finding = Finding(**data)
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return finding


async def list_findings(
    db: AsyncSession,
    session_id: uuid.UUID | None = None,
    severity: str | None = None,
    module: str | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[Finding], int]:
    query = select(Finding).order_by(desc(Finding.created_at))

    if session_id is not None:
        query = query.where(Finding.session_id == session_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if module:
        query = query.where(Finding.module == module)

    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    offset = (page - 1) * per_page
    result = await db.execute(query.offset(offset).limit(per_page))
    items = list(result.scalars().all())

    return items, total


async def get_finding(db: AsyncSession, finding_id: uuid.UUID) -> Finding | None:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    return result.scalar_one_or_none()
