from pydantic import BaseModel
import uuid
from datetime import datetime


class FindingResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    request_id: uuid.UUID | None
    created_at: datetime
    module: str
    severity: str
    title: str
    description: str
    evidence: str | None
    remediation: str | None
    cwe: str | None
    cvss_score: float | None

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    per_page: int
