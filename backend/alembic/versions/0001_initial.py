"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-07-13
"""
import uuid
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("scope", sa.JSON, default=list),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("is_active", sa.Boolean, default=True),
    )

    op.create_table(
        "requests",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("url", sa.Text, nullable=False),
        sa.Column("host", sa.String(512), nullable=False, index=True),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("http_version", sa.String(8), server_default="HTTP/1.1"),
        sa.Column("request_headers", sa.JSON, default=dict),
        sa.Column("request_body", sa.Text, nullable=True),
        sa.Column("request_body_binary", sa.LargeBinary, nullable=True),
        sa.Column("is_body_truncated", sa.Boolean, default=False),
        sa.Column("response_status", sa.Integer, nullable=True, index=True),
        sa.Column("response_reason", sa.String(128), nullable=True),
        sa.Column("response_headers", sa.JSON, nullable=True),
        sa.Column("response_body", sa.Text, nullable=True),
        sa.Column("response_body_binary", sa.LargeBinary, nullable=True),
        sa.Column("response_content_type", sa.String(256), nullable=True),
        sa.Column("response_size_bytes", sa.Integer, nullable=True),
        sa.Column("response_time_ms", sa.Integer, nullable=True),
        sa.Column("is_flagged", sa.Boolean, default=False),
        sa.Column("tags", sa.JSON, default=list),
        sa.Column("api_type", sa.String(32), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("tls_version", sa.String(16), nullable=True),
        sa.Column("tls_cipher", sa.String(128), nullable=True),
    )
    op.create_index("ix_requests_session_timestamp", "requests", ["session_id", "timestamp"])
    op.create_index("ix_requests_host_method", "requests", ["host", "method"])
    op.create_index("ix_requests_req_headers", "requests", ["request_headers"])
    op.create_index("ix_requests_resp_headers", "requests", ["response_headers"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", sa.Uuid, sa.ForeignKey("requests.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("module", sa.String(64), nullable=False),
        sa.Column("severity", sa.Enum("info", "low", "medium", "high", "critical", name="severityenum"), nullable=False, index=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("evidence", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("cwe", sa.String(32), nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
    )
    op.create_index("ix_findings_session_severity", "findings", ["session_id", "severity"])

    op.create_table(
        "match_replace_rules",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("match_type", sa.String(16), nullable=False),
        sa.Column("match_pattern", sa.Text, nullable=False),
        sa.Column("is_regex", sa.Boolean, default=False),
        sa.Column("replacement", sa.Text, nullable=False),
        sa.Column("order", sa.Integer, default=0),
    )

    op.create_table(
        "fuzz_jobs",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("base_request_id", sa.Uuid, sa.ForeignKey("requests.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("request_template", sa.Text, nullable=False),
        sa.Column("attack_type", sa.String(16), server_default="sniper"),
        sa.Column("wordlist_name", sa.String(255), nullable=False),
        sa.Column("wordlist_path", sa.Text, nullable=True),
        sa.Column("positions", sa.JSON, default=list),
        sa.Column("grep_matches", sa.JSON, default=list),
        sa.Column("extractors", sa.JSON, default=list),
        sa.Column("status", sa.String(16), server_default="pending"),
        sa.Column("total_requests", sa.Integer, default=0),
        sa.Column("completed_requests", sa.Integer, default=0),
        sa.Column("rate_limit_rps", sa.Integer, default=10),
        sa.Column("results", sa.JSON, default=list),
    )

    op.create_table(
        "collaborator_interactions",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("token", sa.String(64), nullable=False, index=True),
        sa.Column("interaction_type", sa.Enum("dns", "http", "https", name="interactiontypeenum"), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("raw_payload", sa.Text, nullable=True),
        sa.Column("resolved_to_finding", sa.Boolean, default=False),
        sa.Column("finding_id", sa.Uuid, sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
    )

    op.create_table(
        "interceptor_rules",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scope", sa.String(16), server_default="request"),
        sa.Column("intercept_on_match", sa.Boolean, default=True),
        sa.Column("match_type", sa.String(32), nullable=True),
        sa.Column("match_pattern", sa.Text, nullable=True),
        sa.Column("is_regex", sa.Boolean, default=False),
        sa.Column("order", sa.Integer, default=0),
    )

    op.create_table(
        "intercepted_items",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("request_id", sa.Uuid, sa.ForeignKey("requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("direction", sa.String(16), server_default="request"),
        sa.Column("status", sa.String(16), server_default="paused"),
        sa.Column("modified_method", sa.String(16), nullable=True),
        sa.Column("modified_url", sa.Text, nullable=True),
        sa.Column("modified_headers", sa.JSON, nullable=True),
        sa.Column("modified_body", sa.Text, nullable=True),
        sa.Column("action", sa.String(16), nullable=True),
    )

    op.create_table(
        "session_handling_rules",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("config", sa.JSON, default=dict),
        sa.Column("order", sa.Integer, default=0),
    )

    op.create_table(
        "cookie_jar",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(512), nullable=False, index=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("path", sa.String(512), server_default="/"),
        sa.Column("secure", sa.Boolean, default=False),
        sa.Column("http_only", sa.Boolean, default=False),
        sa.Column("same_site", sa.String(32), nullable=True),
        sa.Column("expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "plugins",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("path", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("hook_type", sa.String(64), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("version", sa.String(32), server_default="1.0.0"),
        sa.Column("config", sa.JSON, default=dict),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("project_data", sa.JSON, default=dict),
    )

    op.create_table(
        "comparer_items",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("left_request_id", sa.Uuid, sa.ForeignKey("requests.id", ondelete="SET NULL"), nullable=True),
        sa.Column("right_request_id", sa.Uuid, sa.ForeignKey("requests.id", ondelete="SET NULL"), nullable=True),
        sa.Column("left_type", sa.String(16), server_default="request"),
        sa.Column("right_type", sa.String(16), server_default="request"),
        sa.Column("left_content", sa.Text, nullable=True),
        sa.Column("right_content", sa.Text, nullable=True),
        sa.Column("left_label", sa.String(255), nullable=True),
        sa.Column("right_label", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("notes", sa.Text, nullable=True),
    )

    op.create_table(
        "websocket_messages",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", sa.Uuid, sa.ForeignKey("requests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("payload", sa.Text, nullable=True),
        sa.Column("is_binary", sa.Boolean, default=False),
        sa.Column("payload_size", sa.Integer, default=0),
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_type", sa.String(16), nullable=False),
        sa.Column("target_url", sa.Text, nullable=True),
        sa.Column("config", sa.JSON, default=dict),
        sa.Column("status", sa.String(16), server_default="pending"),
        sa.Column("progress", sa.Integer, default=0),
        sa.Column("total_tasks", sa.Integer, default=0),
        sa.Column("completed_tasks", sa.Integer, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )


    op.create_table(
        "content_discovery_jobs",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), server_default="pending"),
        sa.Column("wordlist_path", sa.Text, nullable=True),
        sa.Column("discovered_items", sa.JSON, default=list),
        sa.Column("total_requests", sa.Integer, default=0),
        sa.Column("completed_requests", sa.Integer, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config", sa.JSON, default=dict),
    )

    op.create_table(
        "organizer_items",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("request_id", sa.Uuid, sa.ForeignKey("requests.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("tags", sa.JSON, default=list),
        sa.Column("color", sa.String(16), nullable=True),
        sa.Column("is_flagged", sa.Boolean, default=False),
    )

    op.create_table(
        "target_scope_rules",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(16), nullable=False),
        sa.Column("pattern", sa.String(512), nullable=False),
        sa.Column("is_regex", sa.Boolean, default=False),
        sa.Column("protocols", sa.JSON, default=list),
        sa.Column("order", sa.Integer, default=0),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "upstream_proxies",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("enabled", sa.Boolean, default=False),
        sa.Column("host", sa.String(512), nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(8), server_default="http"),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("password", sa.String(512), nullable=True),
        sa.Column("auth_enabled", sa.Boolean, default=False),
        sa.Column("dns_resolution", sa.String(16), server_default="proxy"),
        sa.Column("scope_only", sa.Boolean, default=False),
        sa.Column("exclude_hosts", sa.JSON, default=list),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "clickbandit_configs",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("session_id", sa.Uuid, sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("target_url", sa.String(1024), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("layers", sa.JSON, default=list),
        sa.Column("config", sa.JSON, default=dict),
    )


def downgrade() -> None:
    op.drop_table("upstream_proxies")
    op.drop_table("clickbandit_configs")
    op.drop_table("target_scope_rules")
    op.drop_table("organizer_items")
    op.drop_table("content_discovery_jobs")
    op.drop_table("scan_jobs")
    op.drop_table("websocket_messages")
    op.drop_table("comparer_items")
    op.drop_table("projects")
    op.drop_table("plugins")
    op.drop_table("cookie_jar")
    op.drop_table("session_handling_rules")
    op.drop_table("intercepted_items")
    op.drop_table("interceptor_rules")
    op.drop_table("collaborator_interactions")
    op.drop_table("fuzz_jobs")
    op.drop_table("match_replace_rules")
    op.drop_table("findings")
    op.drop_table("requests")
    op.drop_table("sessions")
