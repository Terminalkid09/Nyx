from pydantic import BaseModel, field_serializer
import uuid
from datetime import datetime

from api.schemas._time import serialize_utc


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

    @field_serializer("created_at")
    def _serialize_created_at(self, value: datetime) -> str:
        """Emit an explicit UTC offset (see api.schemas._time)."""
        return serialize_utc(value)


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    per_page: int
