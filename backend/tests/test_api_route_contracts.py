"""Every read endpoint must answer without a server error.

The coverage matrix (docs/NYX_TEST_MATRIX.md) showed 20 routers with no test
at all. This file is the cheap safety net for them: it walks the app's own
OpenAPI schema, fills required query parameters with harmless values and
asserts the response is never a 5xx. It is not a functional test — a 404 for a
random UUID is a pass — but it catches import errors, broken SQLAlchemy
queries, serialisation bugs and 500s from unhandled None, which is exactly how
the passive SOAP check and the alembic baseline bug slipped through.

Endpoints that change the host (MITM, certificates, capture, firewall, exports,
shutdown) are never called.
"""
import re
import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from main import app

REMOTE_SESSION = str(uuid.uuid4())
ZERO = "00000000-0000-0000-0000-000000000001"

# Anything that touches the OS, the network stack or exports data.
UNSAFE = (
    "/api/shutdown", "/api/ca", "/api/mitm/start", "/api/mitm/stop",
    "/api/mitm/tls", "/api/mitm/quic", "/api/mitm/udp", "/api/mitm/scan-network",
    "/api/network/capture", "/api/proxy/capture", "/api/backup", "/api/export",
    "/api/requests/export", "/api/network/export", "/api/settings/proxy",
    "/api/collaborator/start", "/api/collaborator/stop",
    "/api/auth/jwt/brute", "/api/auth/jwt/crack",
    # Report generation builds a full document from the DB; covered separately.
    "/api/reports/generate",
)


def _concrete(path: str) -> str:
    def repl(match: re.Match) -> str:
        name = match.group(1)
        if name in {"seq", "stream_id", "page", "limit", "hours"}:
            return "1"
        if name == "filename":
            return "missing.json"
        if name == "name":
            return "content_discovery.txt"
        return ZERO

    return re.sub(r"\{([^}]+)\}", repl, path)


def _query(operation: dict) -> dict:
    params: dict[str, str] = {}
    for parameter in operation.get("parameters", []):
        if parameter.get("in") != "query" or not parameter.get("required"):
            continue
        name = parameter["name"]
        if name == "session_id":
            params[name] = REMOTE_SESSION
        elif name in {"q", "query", "search"}:
            params[name] = "x"
        elif name in {"format", "type", "kind"}:
            params[name] = "json"
        else:
            params[name] = "1"
    return params


def _get_operations() -> list[tuple[str, dict]]:
    schema = app.openapi()
    operations = []
    for path, methods in sorted(schema["paths"].items()):
        if not path.startswith("/api/"):
            continue
        if any(path.startswith(prefix) for prefix in UNSAFE):
            continue
        if "get" not in methods:
            continue
        operations.append((path, methods["get"]))
    return operations


OPERATIONS = _get_operations()


@pytest.mark.asyncio
@pytest.mark.parametrize("path,operation", OPERATIONS, ids=[p for p, _ in OPERATIONS])
async def test_read_endpoint_never_returns_5xx(path, operation):
    url = _concrete(path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get(url, params=_query(operation))
    # A 500 means an unhandled exception (the class of bug this guards).
    # 503 is legitimate here: ASGITransport does not run the lifespan, so
    # services the route expects (proxy engine, live audit, interceptor) are
    # absent — but then the route must say so, not crash.
    assert response.status_code != 500, f"{url} -> 500: {response.text[:300]}"
    if response.status_code >= 500:
        assert response.status_code == 503, f"{url} -> {response.status_code}"
        assert response.json().get("detail"), f"{url} -> 503 without detail"


def test_operations_were_discovered():
    """Guard against a refactor silently emptying the parametrised list.

    The threshold is a floor, not the current count: dev-web carries the app
    routes only (the passive network layer and its /api/network endpoints live
    on dev), so ~100 is the right order of magnitude for this branch.
    """
    assert len(OPERATIONS) > 90, f"only {len(OPERATIONS)} GET operations discovered"
