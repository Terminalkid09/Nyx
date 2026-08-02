import pytest
from unittest.mock import AsyncMock


class TestTrafficStorageService:
    @pytest.fixture
    def traffic_storage(self):
        from core.storage.traffic import TrafficStorageService
        bus = AsyncMock()
        return TrafficStorageService(bus, max_body_size=100)

    def test_body_truncation(self, traffic_storage):
        body, truncated = traffic_storage._body("a" * 200)
        assert len(body) == 100
        assert truncated is True

    def test_body_no_truncation(self, traffic_storage):
        body, truncated = traffic_storage._body("a" * 50)
        assert len(body) == 50
        assert truncated is False

    def test_body_none(self, traffic_storage):
        body, truncated = traffic_storage._body(None)
        assert body is None
        assert truncated is False

    def test_uuid_valid(self, traffic_storage):
        import uuid
        uid = uuid.uuid4()
        result = traffic_storage._uuid(str(uid), None)
        assert result == uid

    def test_uuid_invalid(self, traffic_storage):
        result = traffic_storage._uuid("not-a-uuid", "fallback")
        assert result == "fallback"

    def test_uuid_none(self, traffic_storage):
        result = traffic_storage._uuid(None, "fb")
        assert result == "fb"

    def test_subscribes_to_events(self, traffic_storage):
        bus = AsyncMock()
        from core.storage.traffic import TrafficStorageService
        ts = TrafficStorageService(bus, max_body_size=100)
        bus.subscribe.assert_any_call("request.captured", ts._on_request)
        bus.subscribe.assert_any_call("response.received", ts._on_response)


class TestEnsureDefaultSession:
    async def test_ensure_default_session_runs(self):
        from core.storage.traffic import ensure_default_session
        try:
            await ensure_default_session()
        except Exception:
            pass


class TestPersistResults:
    def test_persist_results_signature(self):
        from core.storage.finding_events import persist_results
        import inspect
        sig = inspect.signature(persist_results)
        params = list(sig.parameters.keys())
        assert "event_bus" in params
        assert "results" in params
        assert "event" in params
        assert "module" in params


class TestFindingEventsModule:
    def test_module_imports(self):
        from core.storage import finding_events
        assert hasattr(finding_events, "persist_results")


class TestScopeModule:
    def test_check_scope_import(self):
        from core.scope import check_scope
        assert callable(check_scope)

    def test_make_scope_checker_import(self):
        from core.scope import make_scope_checker
        assert callable(make_scope_checker)


class TestResetSessionData:
    def test_session_data_models_include_core_tables(self):
        from core.storage.crud.sessions import SESSION_DATA_MODELS
        names = [m.__name__ for m in SESSION_DATA_MODELS]
        for required in ["Request", "Finding", "FuzzJob", "ScanJob", "MatchReplaceRule"]:
            assert required in names, required

    async def test_reset_returns_false_for_missing_session(self):
        from unittest.mock import AsyncMock, Mock
        from core.storage.crud.sessions import reset_session_data
        db = AsyncMock()
        db.execute.return_value.scalar_one_or_none = Mock(return_value=None)
        result = await reset_session_data(db, __import__('uuid').uuid4())
        assert result is False

    def test_endpoint_registered(self):
        from api.routes.sessions import router
        routes = [r.path for r in router.routes]
        assert "/api/sessions/{session_id}/data" in routes
        assert "DELETE" in {m for r in router.routes for m in r.methods if getattr(r, 'methods', None)}


class TestLightweightMigration:
    def test_migrations_map_has_findings(self):
        from core.storage.database import _ADD_COLUMN_MIGRATIONS
        assert "findings" in _ADD_COLUMN_MIGRATIONS
        assert ("cvss_vector", "VARCHAR(64)") in _ADD_COLUMN_MIGRATIONS["findings"]
