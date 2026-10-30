"""Burp Suite item exports become the same inventory the OpenAPI importer builds.

The point of the import is deduplication: a real export repeats the same
endpoint hundreds of times with different ids and tokens, and the inventory
must collapse those to one row while keeping the first observed query
parameter names.
"""
import pytest
from httpx import ASGITransport, AsyncClient

from main import app
from modules.importer import burp


def _item(method: str, url: str, host: str, path: str, status: str = "200", mimetype: str = "JSON", protocol: str = "https") -> str:
    return f"""
  <item>
    <url><![CDATA[{url}]]></url>
    <host ip="10.0.0.1">{host}</host>
    <port>443</port>
    <protocol>{protocol}</protocol>
    <method><![CDATA[{method}]]></method>
    <path><![CDATA[{path}]]></path>
    <request base64="true">R0VUIC9odHRwLzEuMQ0K</request>
    <status>{status}</status>
    <mimetype>{mimetype}</mimetype>
  </item>"""


def _export(items: str) -> str:
    return f"""<?xml version="1.0"?>
<items burpVersion="2024.7.1">
{items}
</items>"""


def test_duplicate_requests_collapse_to_one_endpoint():
    document = burp.parse_document(
        _export(
            _item("GET", "https://acme.test/api/users?id=1", "acme.test", "/api/users?id=1")
            + _item("GET", "https://acme.test/api/users?id=2", "acme.test", "/api/users?id=2")
            + _item("POST", "https://acme.test/api/users", "acme.test", "/api/users")
        )
    )

    assert len(document.endpoints) == 2
    assert document.item_count == 3
    by_method = {endpoint.method: endpoint for endpoint in document.endpoints}
    assert by_method["GET"].path == "/api/users"
    assert by_method["GET"].query_parameters == ["id"]
    assert by_method["POST"].query_parameters == []


def test_inventory_shape_matches_the_openapi_importer():
    document = burp.parse_document(
        _export(_item("GET", "https://acme.test/api/users", "acme.test", "/api/users"))
    )
    result = burp.inventory(document, "acme.burp")

    assert result["spec"]["version"] == "burp-xml"
    assert result["spec"]["title"] == "acme"
    assert result["endpoint_count"] == 1
    assert result["method_counts"] == {"get": 1}
    assert result["servers"] == ["acme.test"]
    endpoint = result["endpoints"][0]
    assert endpoint["method"] == "get"
    assert endpoint["url"] == "https://acme.test/api/users"
    assert endpoint["authenticated"] is False


def test_plain_http_capture_is_reported_as_a_warning():
    document = burp.parse_document(
        _export(
            _item(
                "GET",
                "http://legacy.test/login",
                "legacy.test",
                "/login",
                protocol="http",
            )
        )
    )
    codes = [warning["code"] for warning in burp.inventory(document)["warnings"]]
    assert "plaintext_server" in codes


def test_something_that_is_not_a_burp_export_is_rejected():
    with pytest.raises(burp.BurpImportError):
        burp.parse_document("<html><body>Not Burp</body></html>")
    with pytest.raises(burp.BurpImportError):
        burp.parse_document("<items></items>")
    with pytest.raises(burp.BurpImportError):
        burp.parse_document("<items")


def test_doctype_is_rejected_before_the_parser_expands_it():
    payload = """<?xml version="1.0"?>
<!DOCTYPE items [<!ENTITY a "aaaa">]>
<items><item><url>https://acme.test/&a;</url></item></items>"""
    with pytest.raises(burp.BurpImportError, match="DOCTYPE"):
        burp.parse_document(payload)


def test_doctype_is_rejected_after_large_padding():
    """The old check only looked at the first 4096 bytes (bypass)."""
    padding = "<!-- " + ("x" * 8192) + " -->"
    payload = f"""<?xml version="1.0"?>
{padding}
<!DOCTYPE items [<!ENTITY a "aaaa">]>
<items><item><url>https://acme.test/&a;</url></item></items>"""
    with pytest.raises(burp.BurpImportError, match="DOCTYPE"):
        burp.parse_document(payload)


def test_entity_reference_is_rejected_after_large_padding():
    padding = "<!-- " + ("x" * 8192) + " -->"
    payload = f"""<?xml version="1.0"?>
{padding}
<!ENTITY boom "xxxxxxxx">
<items><item><url>https://acme.test/boom</url></item></items>"""
    with pytest.raises(burp.BurpImportError, match="DOCTYPE"):
        burp.parse_document(payload)


@pytest.mark.asyncio
async def test_endpoint_imports_and_applies_scope():
    document = _export(
        _item("GET", "https://acme.test/api/users", "acme.test", "/api/users")
        + _item("GET", "https://admin.acme.test/", "admin.acme.test", "/")
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        session = await client.post("/api/sessions", json={"name": "burp-scope"})
        session_id = session.json()["id"]

        response = await client.post(
            "/api/import/burp",
            json={
                "document": document,
                "filename": "acme.burp",
                "session_id": session_id,
                "apply_scope": True,
            },
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["endpoint_count"] == 2
        assert sorted(body["scope"]["added"]) == ["acme.test", "admin.acme.test"]
        assert body["scope"]["skipped"] == []


@pytest.mark.asyncio
async def test_scope_requires_a_session():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/import/burp",
            json={
                "document": _export(
                    _item("GET", "https://acme.test/x", "acme.test", "/x")
                ),
                "apply_scope": True,
            },
        )
    assert response.status_code == 400
