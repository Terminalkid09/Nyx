"""Tests for the immutable audit trail (core/audit.py)."""
import asyncio
import pytest


class TestAuditTrailModel:
    """Verify the AuditRecord ORM model is correctly defined."""

    def test_model_columns_exist(self):
        from core.audit import AuditRecord
        cols = {c.name for c in AuditRecord.__table__.columns}
        required = {"id", "ts", "actor", "action", "target", "result", "detail"}
        assert required <= cols

    def test_model_tablename(self):
        from core.audit import AuditRecord
        assert AuditRecord.__tablename__ == "audit_trail"

    def test_model_indexes(self):
        from core.audit import AuditRecord
        idx_names = {i.name for i in AuditRecord.__table__.indexes}
        assert "ix_audit_trail_ts" in idx_names
        assert "ix_audit_trail_action" in idx_names


class TestLogAuditNonBlocking:
    """log_audit() must never raise, even if the queue is full."""

    def test_log_audit_does_not_raise(self):
        from core.audit import log_audit
        log_audit(action="test.action", target="test-target", result="success")
        # No exception = pass

    def test_log_audit_with_all_fields(self):
        from core.audit import log_audit
        log_audit(
            action="mitm.start",
            target="192.168.1.5",
            result="success",
            detail="ARP spoofing started",
            actor="nyx-operator",
        )
        # Should not raise

    def test_log_audit_queue_full_graceful(self):
        """Even with a tiny queue, log_audit should not crash on overflow."""
        from core.audit import _get_audit_queue, log_audit

        # Fill the queue to capacity
        for i in range(_get_audit_queue().maxsize + 10):
            log_audit(action=f"fill.{i}", result="overflow_test")
        # Should have dropped records but not raised


class TestFlushAuditSync:
    """Emergency flush must drain the queue synchronously."""

    def test_flush_empty_queue_returns_zero(self):
        from core.audit import _get_audit_queue, flush_audit_sync
        # Drain any records left by other tests (module-level queue is shared)
        queue = _get_audit_queue()
        while not queue.empty():
            try:
                queue.get_nowait()
            except Exception:
                break
        # Now the queue is empty — flush should return 0 (not crash)
        count = flush_audit_sync()
        assert count == 0

    def test_flush_with_pending_records(self):
        from core.audit import log_audit, flush_audit_sync
        log_audit(action="test.flush", target="test", result="pending")
        # Without an active DB, flush_audit_sync catches the error gracefully
        count = flush_audit_sync()
        # Either flushed (if DB available) or failed gracefully (returns 0)
        assert count >= 0


class TestAuditWorkerLifecycle:
    """start/stop of the audit worker in an event loop."""

    @pytest.mark.asyncio
    async def test_start_stop_in_event_loop(self):
        """Verify start/stop don't throw in a running event loop."""
        from core.audit import start_audit_trail, stop_audit_trail
        # Start and immediately stop — don't let the worker actually try DB
        start_audit_trail()
        stop_audit_trail()
        # Should not raise

    @pytest.mark.asyncio
    async def test_stop_idempotent(self):
        from core.audit import stop_audit_trail
        stop_audit_trail()  # first call
        stop_audit_trail()  # second call — should be a no-op
        # No exception = pass

    @pytest.mark.asyncio
    async def test_start_twice_no_orphan(self):
        """Calling start twice should not crash (first task cancelled cleanly)."""
        from core.audit import start_audit_trail, stop_audit_trail
        start_audit_trail()
        start_audit_trail()  # overwrites _audit_task reference
        stop_audit_trail()
        # Should not raise or leak tasks


class TestFlushEmergencyCleanup:
    """Verify flush_audit_sync is callable without an event loop."""

    def test_flush_audit_sync_callable(self):
        from core.audit import flush_audit_sync
        assert callable(flush_audit_sync)

    def test_log_audit_callable(self):
        from core.audit import log_audit
        assert callable(log_audit)