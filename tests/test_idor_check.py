"""
Unit tests for the Smart IDOR check (idor.py).
Tests JSON structure comparison, UUID/int parameter detection, and false-positive avoidance.
"""

import json
import pytest
import sys
import os
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from modules.scanner.active.checks.idor import IdorCheck


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def check():
    return IdorCheck()


def _make_base_request(url: str, method: str = "GET") -> dict:
    return {"method": method, "url": url, "headers": {}, "content": b""}


# ── JSON Schema Helpers ───────────────────────────────────────────────────────

class TestJsonSchema:

    def test_flat_dict_schema(self, check):
        schema = check._json_schema({"id": 1, "name": "Alice", "active": True})
        assert schema == {"id": "int", "name": "str", "active": "bool"}

    def test_nested_dict_schema(self, check):
        schema = check._json_schema({"user": {"id": 1, "name": "Bob"}})
        assert "user" in schema
        assert "user.id" in schema

    def test_list_uses_first_element(self, check):
        schema = check._json_schema([{"id": 1, "role": "admin"}])
        assert "id" in schema
        assert "role" in schema

    def test_empty_object_returns_empty(self, check):
        assert check._json_schema({}) == {}

    def test_same_schema_different_values(self, check):
        s1 = check._json_schema({"id": 10, "name": "Alice"})
        s2 = check._json_schema({"id": 99, "name": "Bob"})
        assert s1 == s2  # Same schema — potential IDOR

    def test_different_schemas_differ(self, check):
        s1 = check._json_schema({"error": "unauthorized"})
        s2 = check._json_schema({"id": 1, "name": "Alice"})
        assert s1 != s2  # Error vs resource — not an IDOR


# ── IDOR Detection Logic ──────────────────────────────────────────────────────

class TestIdorComparison:

    def test_high_confidence_idor_when_same_schema_different_values(self, check):
        orig = {"id": 10, "name": "Alice", "email": "alice@example.com"}
        probe = {"id": 1, "name": "Bob", "email": "bob@example.com"}
        orig_keys = check._json_schema(orig)
        probe_keys = check._json_schema(probe)

        result = check._compare_json_responses(orig, orig_keys, probe, probe_keys, "user_id", 1)
        assert result is not None
        assert result.triggered is True
        assert result.severity == "high"
        assert result.cwe == "CWE-639"
        assert "IDOR" in result.title

    def test_no_finding_when_schemas_differ(self, check):
        orig = {"id": 10, "name": "Alice"}
        probe = {"error": "Not found"}
        orig_keys = check._json_schema(orig)
        probe_keys = check._json_schema(probe)

        result = check._compare_json_responses(orig, orig_keys, probe, probe_keys, "id", 999)
        assert result is None  # Schema mismatch = not an IDOR

    def test_no_finding_when_values_are_identical(self, check):
        obj = {"id": 10, "name": "Alice"}
        orig_keys = check._json_schema(obj)

        result = check._compare_json_responses(obj, orig_keys, obj, orig_keys, "id", 10)
        assert result is None  # Same data = not a different user's record

    def test_no_finding_when_probe_is_empty(self, check):
        orig = {"id": 10, "name": "Alice"}
        orig_keys = check._json_schema(orig)

        result = check._compare_json_responses(orig, orig_keys, {}, {}, "id", 999)
        assert result is None


# ── Parameter Detection ───────────────────────────────────────────────────────

class TestParameterDetection:

    def test_detects_numeric_param(self, check):
        base = _make_base_request("https://api.example.com/users?id=42")
        assert check._is_numeric_or_uuid(base, "id") is True

    def test_detects_uuid_param(self, check):
        base = _make_base_request(
            "https://api.example.com/profile?user_id=550e8400-e29b-41d4-a716-446655440000"
        )
        assert check._is_numeric_or_uuid(base, "user_id") is True

    def test_ignores_non_numeric_string_param(self, check):
        base = _make_base_request("https://api.example.com/search?q=hello")
        assert check._is_numeric_or_uuid(base, "q") is False

    def test_ignores_missing_param(self, check):
        base = _make_base_request("https://api.example.com/page")
        assert check._is_numeric_or_uuid(base, "id") is False

    def test_param_injection_numeric(self, check):
        base = _make_base_request("https://api.example.com/users?id=42")
        modified = check._inject_param(base, "id", "99")
        assert "id=99" in modified["url"]
        assert "id=42" not in modified["url"]

    def test_param_injection_uuid(self, check):
        base = _make_base_request(
            "https://api.example.com/profile?user_id=550e8400-e29b-41d4-a716-446655440000"
        )
        probe_uuid = "00000000-0000-0000-0000-000000000001"
        modified = check._inject_param(base, "user_id", probe_uuid)
        assert probe_uuid in modified["url"]

    def test_inject_does_not_mutate_original(self, check):
        base = _make_base_request("https://api.example.com/users?id=42")
        check._inject_param(base, "id", "99")
        assert "id=42" in base["url"]  # Original unchanged


# ── JSON parsing ─────────────────────────────────────────────────────────────

class TestJsonParsing:

    def test_parses_valid_json(self, check):
        result = check._try_parse_json('{"id": 1}')
        assert result == {"id": 1}

    def test_returns_none_for_html(self, check):
        result = check._try_parse_json("<html>Page not found</html>")
        assert result is None

    def test_returns_none_for_empty(self, check):
        result = check._try_parse_json("")
        assert result is None

    def test_parses_json_array(self, check):
        result = check._try_parse_json('[{"id": 1}, {"id": 2}]')
        assert isinstance(result, list)
        assert len(result) == 2


# ── End-to-End with Mocked HTTP ───────────────────────────────────────────────

@pytest.mark.asyncio
class TestIdorCheckEndToEnd:

    async def test_no_results_when_no_numeric_params(self, check):
        base = _make_base_request("https://api.example.com/search?q=hello")
        results = await check.run(base, ["q"])
        assert results == []

    async def test_no_results_when_params_list_is_empty(self, check):
        base = _make_base_request("https://api.example.com/users?id=1")
        results = await check.run(base, [])
        assert results == []

    @patch("modules.scanner.active.checks.idor.httpx.AsyncClient")
    async def test_triggers_high_confidence_idor_with_json(self, mock_client_cls, check):
        """Simulate: original returns user Alice, probe returns user Bob (same schema)."""
        original_body = json.dumps({"id": 10, "name": "Alice", "email": "alice@example.com"})
        probe_body = json.dumps({"id": 1, "name": "Bob", "email": "bob@example.com"})

        mock_orig_resp = MagicMock()
        mock_orig_resp.status_code = 200
        mock_orig_resp.text = original_body
        mock_orig_resp.content = original_body.encode()

        mock_probe_resp = MagicMock()
        mock_probe_resp.status_code = 200
        mock_probe_resp.text = probe_body
        mock_probe_resp.content = probe_body.encode()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=[mock_orig_resp, mock_probe_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        base = _make_base_request("https://api.example.com/users?id=10")
        results = await check.run(base, ["id"])

        triggered = [r for r in results if r.triggered]
        assert len(triggered) >= 1
        assert triggered[0].severity == "high"
        assert triggered[0].cwe == "CWE-639"

    @patch("modules.scanner.active.checks.idor.httpx.AsyncClient")
    async def test_no_false_positive_when_server_returns_error(self, mock_client_cls, check):
        """Simulate: original returns user data, probe returns 404 error JSON."""
        original_body = json.dumps({"id": 10, "name": "Alice"})
        probe_body = json.dumps({"error": "Not found", "code": 404})

        mock_orig_resp = MagicMock()
        mock_orig_resp.status_code = 200
        mock_orig_resp.text = original_body
        mock_orig_resp.content = original_body.encode()

        mock_probe_resp = MagicMock()
        mock_probe_resp.status_code = 200
        mock_probe_resp.text = probe_body
        mock_probe_resp.content = probe_body.encode()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=[mock_orig_resp, mock_probe_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        base = _make_base_request("https://api.example.com/users?id=10")
        results = await check.run(base, ["id"])

        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 0  # No false positive
