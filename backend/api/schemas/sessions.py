from pydantic import BaseModel
import uuid
from datetime import datetime


class SessionCreate(BaseModel):
    name: str
    scope: list[str] = []
    notes: str | None = None


class SessionUpdate(BaseModel):
    name: str | None = None
    scope: list[str] | None = None
    notes: str | None = None
    is_active: bool | None = None


class SessionResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime
    updated_at: datetime
    scope: list
    notes: str | None
    is_active: bool

    model_config = {"from_attributes": True}
