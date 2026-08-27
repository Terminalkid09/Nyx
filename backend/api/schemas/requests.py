from pydantic import BaseModel, field_serializer
import uuid
from datetime import datetime

from api.schemas._time import serialize_utc


class RequestResponse(BaseModel):
    id: uuid.UUID
    session_id: uuid.UUID
    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    http_version: str
    request_headers: dict
    request_body: str | None
    response_status: int | None
    response_reason: str | None
    response_headers: dict | None
    response_body: str | None
    response_content_type: str | None
    response_size_bytes: int | None
    response_time_ms: int | None
    is_flagged: bool
    tags: list
    api_type: str | None
    tls_version: str | None
    tls_cipher: str | None
    notes: str | None

    model_config = {"from_attributes": True}

    @field_serializer("timestamp")
    def _serialize_timestamp(self, value: datetime) -> str:
        """Emit timestamps with an explicit UTC offset (see api.schemas._time)."""
        return serialize_utc(value)


class RequestListResponse(BaseModel):
    items: list[RequestResponse]
    total: int
    page: int
    per_page: int
