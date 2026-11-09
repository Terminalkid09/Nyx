"""OpenAPI import: inventory, contract warnings, scope application and CLI."""
import copy
import json
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from main import app
from modules.importer.openapi import (
    MAX_DOCUMENT_BYTES,
    OpenAPIImportError,
    contract_warnings,
    inventory,
    parse_document,
    server_hosts,
)

V3_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "ACME API", "version": "2.1"},
    "servers": [
        {"url": "https://{host}/v2", "variables": {"host": {"default": "api.acme.test"}}}
    ],
    "security": [{"bearerAuth": []}],
    "paths": {
        "/items": {
            "parameters": [
                {
                    "name": "tenant",
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string"},
                }
            ],
            "get": {
                "operationId": "listItems",
                "summary": "List items",
                "parameters": [{"$ref": "#/components/parameters/limit"}],
            },
            "post": {
                "requestBody": {"$ref": "#/components/requestBodies/Item"},
                "security": [],
            },
            "x-internal": True,
        },
        "/items/{id}": {
            "delete": {
                "deprecated": True,
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
            }
        },
    },
    "components": {
        "parameters": {
            "limit": {"name": "limit", "in": "query", "schema": {"type": "integer"}}
        },
        "requestBodies": {
            "Item": {"content": {"application/json": {"schema": {"type": "object"}}}}
        },
    },
}

V2_SPEC = """
swagger: "2.0"
info:
  title: Legacy
  version: "1.0"
host: legacy.acme.test
basePath: /api
schemes: [http, https]
security:
  - basicAuth: []
consumes:
  - application/x-www-form-urlencoded
paths:
  /login:
    post:
      parameters:
        - {name: user, in: formData, type: string, required: true}
"""


def _by_method(doc):
    return {(op.method, op.path): op for op in doc.operations}


def test_v3_parsing_resolves_refs_and_servers():
    doc = parse_document(json.dumps(V3_SPEC))

    assert doc.spec_version == "3.0.3"
    assert doc.title == "ACME API"
    assert doc.servers == ("https://api.acme.test/v2",)
    assert server_hosts(doc.servers) == ["api.acme.test"]

    ops = _by_method(doc)
    assert set(ops) == {("get", "/items"), ("post", "/items"), ("delete", "/items/{id}")}

    get = ops[("get", "/items")]
    # Document-level security applies, and the path-level parameter is merged.
    assert get.security == ("bearerAuth",)
    assert get.authenticated is True
    assert {(p.name, p.location, p.schema_type) for p in get.parameters} == {
        ("tenant", "header", "string"),
        ("limit", "query", "integer"),
    }

    post = ops[("post", "/items")]
    # ``security: []`` is an explicit "no auth", not "inherit".
    assert post.security == ()
    assert post.authenticated is False
    assert post.content_types == ("application/json",)

    assert ops[("delete", "/items/{id}")].deprecated is True


def test_inventory_builds_absolute_urls():
    result = inventory(parse_document(json.dumps(V3_SPEC)))

    assert result["endpoint_count"] == 3
    assert result["method_counts"] == {"get": 1, "post": 1, "delete": 1}
    urls = {entry["url"] for entry in result["endpoints"]}
    assert "https://api.acme.test/v2/items" in urls
    assert "https://api.acme.test/v2/items/{id}" in urls
    assert result["spec"] == {"version": "3.0.3", "title": "ACME API", "api_version": "2.1"}


def test_contract_warnings_flag_unauthenticated_and_deprecated():
    warnings = contract_warnings(parse_document(json.dumps(V3_SPEC)))
    codes = {(w["code"], w.get("method"), w.get("path")) for w in warnings}

    assert ("unauthenticated_operation", "post", "/items") in codes
    assert ("deprecated_operation", "delete", "/items/{id}") in codes
    post_warning = next(w for w in warnings if w["code"] == "unauthenticated_operation")
    # A write operation without auth is more serious than a read one.
    assert post_warning["severity"] == "medium"


def test_v2_yaml_parsing_uses_host_schemes_and_consumes():
    doc = parse_document(V2_SPEC)

    assert doc.spec_version == "2.0"
    assert doc.servers == (
        "http://legacy.acme.test/api",
        "https://legacy.acme.test/api",
    )
    (operation,) = doc.operations
    assert operation.method == "post"
    assert operation.security == ("basicAuth",)
    assert operation.content_types == ("application/x-www-form-urlencoded",)
    assert operation.parameters[0].schema_type == "string"

    warnings = contract_warnings(doc)
    assert any(w["code"] == "plaintext_server" and w["severity"] == "medium" for w in warnings)


def test_untyped_parameter_is_reported():
    spec = copy.deepcopy(V3_SPEC)
    spec["paths"]["/search"] = {
        "get": {"parameters": [{"name": "q", "in": "query"}]}
    }
    warnings = contract_warnings(parse_document(json.dumps(spec)))

    untyped = [w for w in warnings if w["code"] == "untyped_parameter"]
    assert untyped and "q" in untyped[0]["message"]


def test_no_servers_and_no_operations():
    warnings = contract_warnings(parse_document('{"openapi": "3.1.0", "paths": {}}'))
    codes = {w["code"] for w in warnings}
    assert {"no_servers", "no_operations"} <= codes


@pytest.mark.parametrize(
    "document",
    [
        "",
        "   ",
        "- not\n- a mapping",
        "{}",
        '{"swagger": "1.2"}',
        '{"openapi": "2.0"}',
    ],
)
def test_malformed_documents_are_rejected(document):
    with pytest.raises(OpenAPIImportError):
        parse_document(document)


def test_remote_and_broken_refs_are_rejected():
    with pytest.raises(OpenAPIImportError, match="external"):
        parse_document(
            json.dumps(
                {
                    "openapi": "3.0.0",
                    "paths": {"/a": {"get": {"parameters": [{"$ref": "https://x.test/p.json"}]}}},
                }
            )
        )
    with pytest.raises(OpenAPIImportError, match="unresolvable"):
        parse_document(
            json.dumps(
                {
                    "openapi": "3.0.0",
                    "paths": {"/a": {"get": {"parameters": [{"$ref": "#/nope"}]}}},
                }
            )
        )


def test_oversized_document_is_rejected():
    with pytest.raises(OpenAPIImportError, match="larger"):
        parse_document("x" * (MAX_DOCUMENT_BYTES + 1))


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_import_endpoint_returns_the_inventory(client):
    async with client as c:
        response = await c.post(
            "/api/import/openapi",
            json={"document": json.dumps(V3_SPEC), "filename": "../../spec.json"},
        )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["endpoint_count"] == 3
    # A filename is echoed for display only: no path survives.
    assert payload["filename"] == "spec.json"


@pytest.mark.asyncio
async def test_import_endpoint_rejects_a_broken_document(client):
    async with client as c:
        response = await c.post("/api/import/openapi", json={"document": "not: [valid"})
    assert response.status_code == 400
    assert "not valid" in response.json()["detail"]


@pytest.mark.asyncio
async def test_import_endpoint_requires_a_session_to_apply_scope(client):
    async with client as c:
        response = await c.post(
            "/api/import/openapi",
            json={"document": json.dumps(V3_SPEC), "apply_scope": True},
        )
    assert response.status_code == 400
    assert "session_id" in response.json()["detail"]


@pytest.mark.asyncio
async def test_import_endpoint_rejects_unknown_session(client):
    async with client as c:
        response = await c.post(
            "/api/import/openapi",
            json={
                "document": json.dumps(V3_SPEC),
                "apply_scope": True,
                "session_id": str(uuid.uuid4()),
            },
        )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_apply_scope_is_idempotent(client):
    async with client as c:
        created = await c.post("/api/sessions", json={"name": "openapi-import"})
        assert created.status_code == 201, created.text
        session_id = created.json()["id"]

        first = await c.post(
            "/api/import/openapi",
            json={
                "document": json.dumps(V3_SPEC),
                "apply_scope": True,
                "session_id": session_id,
            },
        )
        assert first.status_code == 200, first.text
        assert first.json()["scope"] == {"added": ["api.acme.test"], "skipped": []}

        second = await c.post(
            "/api/import/openapi",
            json={
                "document": json.dumps(V3_SPEC),
                "apply_scope": True,
                "session_id": session_id,
            },
        )
        assert second.status_code == 200
        assert second.json()["scope"] == {"added": [], "skipped": ["api.acme.test"]}

        rules = await c.get("/api/scope/", params={"session_id": session_id})
        assert rules.status_code == 200, rules.text
        patterns = [r["pattern"] for r in rules.json()]
        assert patterns.count("api.acme.test") == 1


def test_cli_prints_the_inventory(tmp_path, capsys):
    from nyx_cli import main

    spec = tmp_path / "spec.yaml"
    spec.write_text(V2_SPEC, encoding="utf-8")

    assert main(["import", "openapi", str(spec), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["endpoint_count"] == 1
    assert payload["servers"][0].startswith("http://")

    out = tmp_path / "inventory.json"
    assert main(["import", "openapi", str(spec), "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["endpoint_count"] == 1


def test_cli_exit_codes(tmp_path, capsys):
    from nyx_cli import main

    assert main(["import", "openapi", str(tmp_path / "missing.yaml")]) == 2

    broken = tmp_path / "broken.yaml"
    broken.write_text("swagger: '1.2'", encoding="utf-8")
    assert main(["import", "openapi", str(broken)]) == 2

    # The v2 sample declares a plaintext server: --fail-on medium must trip.
    spec = tmp_path / "spec.yaml"
    spec.write_text(V2_SPEC, encoding="utf-8")
    assert main(["import", "openapi", str(spec), "--fail-on", "medium"]) == 1
    assert main(["import", "openapi", str(spec), "--fail-on", "critical"]) == 0
