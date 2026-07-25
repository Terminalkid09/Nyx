import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import (
    String, Text, Integer, Boolean, DateTime, ForeignKey,
    Enum, Index, JSON, LargeBinary, Uuid
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class SeverityEnum(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InteractionTypeEnum(str, enum.Enum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"


def _now():
    return datetime.now(timezone.utc)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    scope: Mapped[dict] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    requests: Mapped[list["Request"]] = relationship(back_populates="session")
    findings: Mapped[list["Finding"]] = relationship(back_populates="session")


class Request(Base):
    __tablename__ = "requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    method: Mapped[str] = mapped_column(String(16))
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(512), index=True)
    path: Mapped[str] = mapped_column(Text)
    http_version: Mapped[str] = mapped_column(String(8), default="HTTP/1.1")
    request_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    request_body: Mapped[str | None] = mapped_column(Text)
    request_body_binary: Mapped[bytes | None] = mapped_column(LargeBinary)
    is_body_truncated: Mapped[bool] = mapped_column(Boolean, default=False)

    response_status: Mapped[int | None] = mapped_column(Integer, index=True)
    response_reason: Mapped[str | None] = mapped_column(String(128))
    response_headers: Mapped[dict | None] = mapped_column(JSON)
    response_body: Mapped[str | None] = mapped_column(Text)
    response_body_binary: Mapped[bytes | None] = mapped_column(LargeBinary)
    response_content_type: Mapped[str | None] = mapped_column(String(256))
    response_size_bytes: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[int | None] = mapped_column(Integer)

    is_flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[dict] = mapped_column(JSON, default=list)
    api_type: Mapped[str | None] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)

    tls_version: Mapped[str | None] = mapped_column(String(16))
    tls_cipher: Mapped[str | None] = mapped_column(String(128))

    session: Mapped["Session"] = relationship(back_populates="requests")
    findings: Mapped[list["Finding"]] = relationship(back_populates="request")

    __table_args__ = (
        Index("ix_requests_session_timestamp", "session_id", "timestamp"),
        Index("ix_requests_host_method", "host", "method"),
        Index("ix_requests_req_headers", "request_headers"),
        Index("ix_requests_resp_headers", "response_headers"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("requests.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    module: Mapped[str] = mapped_column(String(64))
    severity: Mapped[SeverityEnum] = mapped_column(Enum(SeverityEnum), index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column()

    session: Mapped["Session"] = relationship(back_populates="findings")
    request: Mapped["Request | None"] = relationship(back_populates="findings")

    __table_args__ = (
        Index("ix_findings_session_severity", "session_id", "severity"),
    )


class MatchReplaceRule(Base):
    __tablename__ = "match_replace_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    name: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(String(16))
    match_type: Mapped[str] = mapped_column(String(16))
    match_pattern: Mapped[str] = mapped_column(Text)
    is_regex: Mapped[bool] = mapped_column(Boolean, default=False)
    replacement: Mapped[str] = mapped_column(Text)
    order: Mapped[int] = mapped_column(Integer, default=0)


class FuzzJob(Base):
    __tablename__ = "fuzz_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    base_request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("requests.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    request_template: Mapped[str] = mapped_column(Text)
    attack_type: Mapped[str] = mapped_column(String(16), default="sniper")
    wordlist_name: Mapped[str] = mapped_column(String(255))
    wordlist_path: Mapped[str | None] = mapped_column(Text)
    positions: Mapped[dict] = mapped_column(JSON, default=list)
    grep_matches: Mapped[dict] = mapped_column(JSON, default=list)
    extractors: Mapped[dict] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    completed_requests: Mapped[int] = mapped_column(Integer, default=0)
    rate_limit_rps: Mapped[int] = mapped_column(Integer, default=10)
    results: Mapped[dict] = mapped_column(JSON, default=list)


class CollaboratorInteraction(Base):
    __tablename__ = "collaborator_interactions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    token: Mapped[str] = mapped_column(String(64), index=True)
    interaction_type: Mapped[InteractionTypeEnum] = mapped_column(Enum(InteractionTypeEnum))
    source_ip: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    raw_payload: Mapped[str | None] = mapped_column(Text)
    resolved_to_finding: Mapped[bool] = mapped_column(Boolean, default=False)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))

    # HTTP/HTTPS interaction details
    method: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(Text)
    request_headers: Mapped[dict | None] = mapped_column(JSON)
    body: Mapped[str | None] = mapped_column(Text)
    user_agent: Mapped[str | None] = mapped_column(String(512))

    # DNS interaction details
    query_type: Mapped[str | None] = mapped_column(String(16))
    query_name: Mapped[str | None] = mapped_column(String(512))


class InterceptorRule(Base):
    __tablename__ = "interceptor_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    name: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(String(16), default="request")
    intercept_on_match: Mapped[bool] = mapped_column(Boolean, default=True)
    match_type: Mapped[str | None] = mapped_column(String(32))
    match_pattern: Mapped[str | None] = mapped_column(Text)
    is_regex: Mapped[bool] = mapped_column(Boolean, default=False)
    order: Mapped[int] = mapped_column(Integer, default=0)


class InterceptedItem(Base):
    __tablename__ = "intercepted_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("requests.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    direction: Mapped[str] = mapped_column(String(16), default="request")
    status: Mapped[str] = mapped_column(String(16), default="paused")
    modified_method: Mapped[str | None] = mapped_column(String(16))
    modified_url: Mapped[str | None] = mapped_column(Text)
    modified_headers: Mapped[dict | None] = mapped_column(JSON)
    modified_body: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str | None] = mapped_column(String(16))


class SessionHandlingRule(Base):
    __tablename__ = "session_handling_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(32))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    order: Mapped[int] = mapped_column(Integer, default=0)


class CookieJar(Base):
    __tablename__ = "cookie_jar"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    domain: Mapped[str] = mapped_column(String(512), index=True)
    name: Mapped[str] = mapped_column(String(256))
    value: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(String(512), default="/")
    secure: Mapped[bool] = mapped_column(Boolean, default=False)
    http_only: Mapped[bool] = mapped_column(Boolean, default=False)
    same_site: Mapped[str | None] = mapped_column(String(32))
    expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Plugin(Base):
    __tablename__ = "plugins"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    path: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    hook_type: Mapped[str] = mapped_column(String(64))
    description: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    project_data: Mapped[dict] = mapped_column(JSON, default=dict)


class ComparerItem(Base):
    __tablename__ = "comparer_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    left_request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("requests.id", ondelete="SET NULL"))
    right_request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("requests.id", ondelete="SET NULL"))
    left_type: Mapped[str] = mapped_column(String(16), default="request")
    right_type: Mapped[str] = mapped_column(String(16), default="request")
    left_content: Mapped[str | None] = mapped_column(Text)
    right_content: Mapped[str | None] = mapped_column(Text)
    left_label: Mapped[str | None] = mapped_column(String(255))
    right_label: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    notes: Mapped[str | None] = mapped_column(Text)


class WebSocketMessage(Base):
    __tablename__ = "websocket_messages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("requests.id", ondelete="CASCADE"))
    direction: Mapped[str] = mapped_column(String(8))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    payload: Mapped[str | None] = mapped_column(Text)
    is_binary: Mapped[bool] = mapped_column(Boolean, default=False)
    payload_size: Mapped[int] = mapped_column(Integer, default=0)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    scan_type: Mapped[str] = mapped_column(String(16))
    target_url: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    total_tasks: Mapped[int] = mapped_column(Integer, default=0)
    completed_tasks: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ContentDiscoveryJob(Base):
    __tablename__ = "content_discovery_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    wordlist_path: Mapped[str | None] = mapped_column(Text)
    discovered_items: Mapped[dict] = mapped_column(JSON, default=list)
    total_requests: Mapped[int] = mapped_column(Integer, default=0)
    completed_requests: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    config: Mapped[dict] = mapped_column(JSON, default=dict)


class OrganizerItem(Base):
    __tablename__ = "organizer_items"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    request_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("requests.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[dict] = mapped_column(JSON, default=list)
    color: Mapped[str | None] = mapped_column(String(16))
    is_flagged: Mapped[bool] = mapped_column(Boolean, default=False)


class TargetScopeRule(Base):
    __tablename__ = "target_scope_rules"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    name: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(16))
    pattern: Mapped[str] = mapped_column(String(512))
    is_regex: Mapped[bool] = mapped_column(Boolean, default=False)
    match_domain: Mapped[bool] = mapped_column(Boolean, default=False)
    protocols: Mapped[dict] = mapped_column(JSON, default=list)
    order: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CustomScannerCheck(Base):
    __tablename__ = "custom_scanner_checks"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    match_type: Mapped[str] = mapped_column(String(16), default="response_body")
    match_pattern: Mapped[str] = mapped_column(String(1024))
    is_regex: Mapped[bool] = mapped_column(Boolean, default=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ClickbanditConfig(Base):
    __tablename__ = "clickbandit_configs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    target_url: Mapped[str] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)
    layers: Mapped[dict] = mapped_column(JSON, default=list)
    config: Mapped[dict] = mapped_column(JSON, default=dict)


class UpstreamProxy(Base):
    __tablename__ = "upstream_proxies"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    host: Mapped[str] = mapped_column(String(512), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default="http")
    username: Mapped[str | None] = mapped_column(String(255))
    password: Mapped[str | None] = mapped_column(String(512))
    auth_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    dns_resolution: Mapped[str] = mapped_column(String(16), default="proxy")
    scope_only: Mapped[bool] = mapped_column(Boolean, default=False)
    exclude_hosts: Mapped[dict] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class RepeaterTab(Base):
    __tablename__ = "repeater_tabs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class RepeaterHistory(Base):
    __tablename__ = "repeater_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tab_id: Mapped[str] = mapped_column(String(36), ForeignKey("repeater_tabs.id", ondelete="CASCADE"))
    method: Mapped[str] = mapped_column(String(10))
    url: Mapped[str] = mapped_column(Text)
    headers: Mapped[dict] = mapped_column(JSON)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timestamp: Mapped[str] = mapped_column(String(30))
