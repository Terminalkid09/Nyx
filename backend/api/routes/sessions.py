from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_db
from api.schemas.sessions import SessionCreate, SessionUpdate, SessionResponse
from core.storage.crud.sessions import (
    create_session, get_session, list_sessions,
    update_session, delete_session,
)
import uuid

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


@router.get("", response_model=list[SessionResponse])
async def list_all_sessions(db: AsyncSession = Depends(get_db)):
    return await list_sessions(db)


@router.post("", response_model=SessionResponse, status_code=201)
async def create_new_session(body: SessionCreate, db: AsyncSession = Depends(get_db)):
    return await create_session(db, name=body.name, scope=body.scope)


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session_by_id(session_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    session = await get_session(db, session_id)
    if not session:
        raise HTTPException(404, detail="Session not found")
    return session


@router.put("/{session_id}", response_model=SessionResponse)
async def update_session_by_id(session_id: uuid.UUID, body: SessionUpdate, db: AsyncSession = Depends(get_db)):
    session = await update_session(db, session_id, **body.model_dump(exclude_none=True))
    if not session:
        raise HTTPException(404, detail="Session not found")
    return session


@router.delete("/{session_id}", status_code=204)
async def delete_session_by_id(session_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    deleted = await delete_session(db, session_id)
    if not deleted:
        raise HTTPException(404, detail="Session not found")
