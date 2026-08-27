from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel
import uuid

class NyxEvent(BaseModel):
    type: str
    timestamp: datetime | None = None

    def model_post_init(self, _):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

class RequestCapturedEvent(NyxEvent):
    type: Literal["request.captured"] = "request.captured"
    request_id: uuid.UUID
    session_id: uuid.UUID
    method: str
    url: str
    host: str
    path: str
    request_headers: dict
    request_body: str | None
    response_status: int | None = None
    response_headers: dict | None = None
    response_body: str | None = None
    response_time_ms: int | None = None

class ResponseReceivedEvent(NyxEvent):
    type: Literal["response.received"] = "response.received"
    request_id: uuid.UUID
    session_id: uuid.UUID
    status: int
    headers: dict
    body: str | None
    content_type: str | None
    size_bytes: int
    response_time_ms: int


class FindingCreatedEvent(NyxEvent):
    type: Literal["finding.created"] = "finding.created"
    finding_id: uuid.UUID
    session_id: uuid.UUID
    request_id: uuid.UUID | None
    module: str
    severity: str
    title: str


class ActiveScanStartedEvent(NyxEvent):
    type: Literal["scan.active.started"] = "scan.active.started"
    job_id: uuid.UUID
    request_id: uuid.UUID


class ActiveScanCompletedEvent(NyxEvent):
    type: Literal["scan.active.completed"] = "scan.active.completed"
    job_id: uuid.UUID
    findings_count: int


class FuzzProgressEvent(NyxEvent):
    type: Literal["fuzz.progress"] = "fuzz.progress"
    job_id: uuid.UUID
    completed: int
    total: int
    last_payload: str


class CollaboratorHitEvent(NyxEvent):
    type: Literal["collaborator.hit"] = "collaborator.hit"
    token: str
    interaction_type: str
    source_ip: str
