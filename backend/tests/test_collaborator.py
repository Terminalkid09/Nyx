import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_result():
    result = AsyncMock()
    scalars_mock = AsyncMock()
    scalars_mock.all = MagicMock(return_value=[])
    result.scalars = MagicMock(return_value=scalars_mock)
    return result


@pytest.fixture
def mock_db(mock_result):
    db = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    async def execute(stmt):
        return mock_result
    db.execute = execute
    return db


class TestCollaboratorTokenGeneration:
    def test_generate_token_returns_all_fields(self):
        import asyncio
        from api.routes.collaborator import generate_token
        resp = asyncio.run(generate_token())
        assert resp.token
        assert len(resp.token) == 16
        assert resp.subdomain
        assert resp.dns_payload
        assert resp.http_payload
        assert resp.log4shell_payload
        assert resp.ssrf_payload
        assert resp.api_callback_url
        assert resp.token in resp.subdomain
        assert resp.token in resp.dns_payload
        assert resp.token in resp.http_payload
        assert resp.api_callback_url.endswith(resp.token)

    def test_tokens_are_unique(self):
        import asyncio
        from api.routes.collaborator import generate_token
        tokens = set()
        for _ in range(100):
            resp = asyncio.run(generate_token())
            tokens.add(resp.token)
        assert len(tokens) == 100


class TestCollaboratorCallback:
    @pytest.mark.asyncio
    async def test_callback_stores_interaction(self, mock_db, mock_result):
        from api.routes.collaborator import collaborator_callback
        from core.storage.models import CollaboratorInteraction

        mock_request = MagicMock()
        mock_request.body = AsyncMock(return_value=b"test body")
        mock_request.headers = {"user-agent": "test-agent", "content-type": "text/plain"}
        mock_request.client.host = "127.0.0.1"
        mock_request.method = "POST"
        mock_request.url = "http://test/api/collaborator/callback/testtoken"

        await collaborator_callback("testtoken", mock_request, mock_db)

        call_args = mock_db.add.call_args
        assert call_args is not None
        interaction = call_args[0][0]
        assert interaction.token == "testtoken"
        assert interaction.method == "POST"
        assert "test-agent" in (interaction.user_agent or "")
        assert interaction.source_ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_callback_handles_get_request(self, mock_db):
        from api.routes.collaborator import collaborator_callback

        mock_request = MagicMock()
        mock_request.body = AsyncMock(return_value=b"")
        mock_request.headers = {}
        mock_request.client.host = "10.0.0.1"
        mock_request.method = "GET"
        mock_request.url = "http://oast.nyx.local/api/collaborator/callback/abc123"

        await collaborator_callback("abc123", mock_request, mock_db)

        call_args = mock_db.add.call_args
        interaction = call_args[0][0]
        assert interaction.token == "abc123"
        assert interaction.method == "GET"
        assert interaction.source_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_callback_captures_path_as_token(self, mock_db):
        from api.routes.collaborator import collaborator_callback

        mock_request = MagicMock()
        mock_request.body = AsyncMock(return_value=b"payload")
        mock_request.headers = {"user-agent": "curl/8.0"}
        mock_request.client.host = "192.168.1.1"
        mock_request.method = "POST"
        mock_request.url = "http://nyx.local:8000/api/collaborator/callback/mytoken123"

        await collaborator_callback("mytoken123", mock_request, mock_db)

        call_args = mock_db.add.call_args
        interaction = call_args[0][0]
        assert interaction.token == "mytoken123"
        assert interaction.method == "POST"
        assert interaction.user_agent == "curl/8.0"
        assert interaction.body == "payload"
        assert interaction.source_ip == "192.168.1.1"


class TestCollaboratorListInteractions:
    @pytest.mark.asyncio
    async def test_list_all_interactions(self, mock_db, mock_result):
        from api.routes.collaborator import list_interactions
        from core.storage.models import CollaboratorInteraction
        from datetime import datetime, timezone

        interactions = [
            CollaboratorInteraction(
                token="abc", interaction_type="http", source_ip="1.2.3.4",
                received_at=datetime.now(timezone.utc),
                method="GET", url="http://test.com/",
            ),
            CollaboratorInteraction(
                token="def", interaction_type="dns", source_ip="5.6.7.8",
                received_at=datetime.now(timezone.utc),
                query_type="A", query_name="test.oast.local",
            ),
        ]
        mock_result.scalars.return_value.all.return_value = interactions

        result = await list_interactions(token=None, since=None, db=mock_db)
        assert len(result) == 2
        assert result[0].token == "abc"
        assert result[1].token == "def"

    @pytest.mark.asyncio
    async def test_list_filter_by_token(self, mock_db, mock_result):
        from api.routes.collaborator import list_interactions

        result = await list_interactions(token="specific_token", since=None, db=mock_db)
        assert result == []

    @pytest.mark.asyncio
    async def test_list_filter_by_since(self, mock_db, mock_result):
        from api.routes.collaborator import list_interactions

        since_str = "2020-01-01T00:00:00+00:00"
        result = await list_interactions(token=None, since=since_str, db=mock_db)
        assert result == []

    @pytest.mark.asyncio
    async def test_list_filter_by_both(self, mock_db, mock_result):
        from api.routes.collaborator import list_interactions

        result = await list_interactions(
            token="my_token", since="2020-01-01T00:00:00+00:00", db=mock_db
        )
        assert result == []


class TestCollaboratorWebhook:
    @pytest.mark.asyncio
    async def test_webhook_backward_compat(self, mock_db):
        from api.routes.collaborator import receive_interaction, CollaboratorWebhookPayload
        from core.storage.models import InteractionTypeEnum

        mock_request = MagicMock()
        mock_request.app.state.ws_manager = None
        payload = CollaboratorWebhookPayload(
            token="old_token", type="dns", source_ip="9.9.9.9", raw="test"
        )

        result = await receive_interaction(mock_request, payload, mock_db)
        assert result["status"] == "ok"

        call_args = mock_db.add.call_args
        interaction = call_args[0][0]
        assert interaction.token == "old_token"
        assert interaction.interaction_type == InteractionTypeEnum.DNS
        assert interaction.source_ip == "9.9.9.9"
        assert interaction.raw_payload == "test"


class TestCollaboratorHealth:
    @pytest.mark.asyncio
    async def test_health_endpoint(self):
        from api.routes.collaborator import collaborator_health
        result = await collaborator_health()
        assert result["status"] == "ok"
        assert result["service"] == "collaborator"
        assert result["mode"] == "embedded"


class TestAutoExploitCollaboratorIntegration:
    def test_engine_replaces_collaborator_placeholder(self):
        from modules.auto_exploit.engine import AutoExploitEngine
        engine = AutoExploitEngine()
        finding = {
            "cwe": "CWE-78",
            "url": "http://target.com/search",
            "param": "q",
        }
        exploit = engine.generate_exploit(finding)
        assert exploit is not None
        code = exploit["code"]
        assert "COLLABORATOR" not in code

    def test_engine_replaces_collaborator_in_extraction(self):
        from modules.auto_exploit.engine import AutoExploitEngine
        engine = AutoExploitEngine()
        finding = {
            "cwe": "CWE-79",
            "url": "http://target.com/search",
            "param": "q",
        }
        exploit = engine.generate_exploit(finding)
        assert exploit is not None
        if exploit.get("extraction") and exploit["extraction"].get("code"):
            assert "COLLABORATOR" not in exploit["extraction"]["code"]

    def test_all_cwes_replace_collaborator(self):
        from modules.auto_exploit.engine import AutoExploitEngine
        from modules.auto_exploit.payloads import CWE_PAYLOADS
        engine = AutoExploitEngine()
        for cwe in CWE_PAYLOADS:
            finding = {"cwe": cwe, "url": "http://target.com/", "param": "test"}
            for lang in ["curl", "python", "js", "html"]:
                exploit = engine.generate_exploit(finding, language=lang)
                if exploit and "COLLABORATOR" in CWE_PAYLOADS[cwe].get("payloads", {}).get(lang, {}).get("code", ""):
                    assert "COLLABORATOR" not in exploit["code"], f"{cwe} with {lang} still has placeholder"

    def test_generate_all_replaces_collaborator(self):
        from modules.auto_exploit.engine import AutoExploitEngine
        engine = AutoExploitEngine()
        findings = [
            {"cwe": "CWE-79", "url": "http://a.com", "param": "q"},
            {"cwe": "CWE-89", "url": "http://b.com", "param": "id"},
            {"cwe": "CWE-78", "url": "http://c.com", "param": "cmd"},
        ]
        exploits = engine.generate_all(findings, language="curl")
        for e in exploits:
            assert "COLLABORATOR" not in e["code"]
