"""Immutable audit trail for operator accountability.

Every significant action (MITM start/stop, scan launch, project change,
export, CA install/remove) is logged with an auto-incrementing sequence number,
timestamp, operator identity, action, target, and result. The trail is append-
only — records are never modified or deleted, providing non-repudiation for
compliance and incident response.

The trail is stored in the same SQLite database as traffic, kept small by a
separate retention policy (1 year default vs 7 days for traffic).
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Integer, String, DateTime, Text, Index
from sqlalchemy.orm import Mapped, mapped_column

from core.storage.models import Base

logger = logging.getLogger(__name__)


# ── Database model ──────────────────────────────────────────────────────────

class AuditRecord(Base):
    __tablename__ = "audit_trail"
    __table_args__ = (
        Index("ix_audit_trail_ts", "ts"),
        Index("ix_audit_trail_action", "action"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    actor: Mapped[str] = mapped_column(String(128), default="nyx-operator")
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    result: Mapped[str] = mapped_column(String(32), default="success")
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


# ── Async writer (fire-and-forget, never blocks the caller) ─────────────────

# Created lazily: an asyncio.Queue is bound to the event loop that created it.
# At module import there is no running loop, and in tests the loop a queue was
# bound to can be closed later — put_nowait then raises "Event loop is
# closed" and crashes the caller. We (re)create the queue for the *current*
# running loop on every access instead.
_audit_queue: asyncio.Queue | None = None
_audit_task: asyncio.Task | None = None


def _get_audit_queue() -> asyncio.Queue:
    """Return the audit queue bound to the current running loop.

    The queue is recreated lazily because ``asyncio.Queue`` binds to the
    event loop that created it: at module import there is no loop, and in
    tests a loop the queue was bound to can be closed later — put_nowait
    would then raise "Event loop is closed". With no running loop (sync
    context) the existing queue is reused as-is.
    """
    global _audit_queue
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if _audit_queue is None:
        _audit_queue = asyncio.Queue(maxsize=500)
    elif loop is not None and getattr(_audit_queue, "_loop", None) is not loop:
        _audit_queue = asyncio.Queue(maxsize=500)
    return _audit_queue


async def _audit_worker():
    """Drain the audit queue and persist records in batches."""
    from core.storage.database import AsyncSessionLocal

    while True:
        try:
            queue = _get_audit_queue()
            batch: list[dict] = []
            # Collect the first record, then drain whatever else is queued
            batch.append(await queue.get())
            while not queue.empty():
                try:
                    batch.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            async with AsyncSessionLocal() as db:
                for entry in batch:
                    db.add(AuditRecord(**entry))
                await db.commit()
                logger.debug("Audit trail: persisted %d record(s)", len(batch))

            for _ in batch:
                queue.task_done()

        except asyncio.CancelledError:
            # Flush remaining queue before exiting
            remaining: list[dict] = []
            while not queue.empty():
                try:
                    remaining.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if remaining:
                try:
                    async with AsyncSessionLocal() as db:
                        for entry in remaining:
                            db.add(AuditRecord(**entry))
                        await db.commit()
                    logger.info("Audit trail: flushed %d record(s) on shutdown", len(remaining))
                except Exception as e:
                    logger.warning("Audit trail flush failed on shutdown: %s", e)
            return
        except Exception as e:
            logger.warning("Audit trail worker error: %s", e)


def start_audit_trail():
    """Launch the audit persistence worker (called once at startup)."""
    global _audit_task
    try:
        loop = asyncio.get_running_loop()
        _audit_task = loop.create_task(_audit_worker())
        logger.info("Audit trail worker started")
    except RuntimeError:
        logger.warning("No running event loop — audit trail disabled")


def stop_audit_trail():
    """Cancel the audit worker and flush pending records."""
    global _audit_task
    if _audit_task:
        _audit_task.cancel()
        _audit_task = None


def flush_audit_sync() -> int:
    """Synchronous emergency flush — drains the queue without an event loop.

    Used by atexit / signal handlers where asyncio (and SQLAlchemy's async
    greenlet context) is unavailable. Writes directly via the stdlib sqlite3
    driver, which works in any thread/context.

    Returns the number of records flushed (0 if the queue was empty).
    """
    import sqlite3
    from core.config import settings

    global _audit_task
    if _audit_task:
        _audit_task.cancel()
        _audit_task = None

    queue = _audit_queue
    drained: list[dict] = []
    if queue is not None:
        # Guarded: in a sync/atexit context the queue's loop may be closed,
        # and get_nowait would then raise RuntimeError on wake-up.
        while not queue.empty():
            try:
                drained.append(queue.get_nowait())
            except (asyncio.QueueEmpty, RuntimeError):
                break

    if not drained:
        return 0

    try:
        # Extract the sqlite file path from the DATABASE_URL
        # (e.g. "sqlite+aiosqlite:///nyx.db" → "nyx.db")
        db_url = settings.DATABASE_URL
        path = db_url.split("///", 1)[-1] if "///" in db_url else "nyx.db"
        conn = sqlite3.connect(path, timeout=5)
        try:
            now = datetime.now(timezone.utc).isoformat()
            for entry in drained:
                conn.execute(
                    "INSERT INTO audit_trail (ts, actor, action, target, result, detail) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        entry.get("ts") or now,
                        entry.get("actor") or "nyx-operator",
                        entry.get("action", ""),
                        entry.get("target"),
                        entry.get("result", "success"),
                        entry.get("detail"),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        logger.info("Audit trail: emergency-flushed %d record(s)", len(drained))
        return len(drained)
    except Exception as e:
        logger.warning("Audit trail emergency flush failed: %s", e)
        return 0


def log_audit(
    action: str,
    target: str | None = None,
    result: str = "success",
    detail: str | None = None,
    actor: str = "nyx-operator",
) -> None:
    """Record an auditable action. Non-blocking — never raises."""
    try:
        _get_audit_queue().put_nowait({
            "action": action,
            "target": target,
            "result": result,
            "detail": detail,
            "actor": actor,
            "ts": datetime.now(timezone.utc),
        })
    except asyncio.QueueFull:
        logger.warning("Audit queue full — dropping record: %s", action)
    except RuntimeError:
        # Event loop is closed (test teardown / backend shutdown). The audit
        # trail is fire-and-forget — drop rather than crash the caller.
        logger.debug("Audit queue unavailable (loop closed) — dropping record: %s", action)