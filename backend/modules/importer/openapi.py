"""OpenAPI 2.0 / 3.x reader: endpoint inventory and contract warnings.

The parser is deliberately offline and side-effect free. It resolves only local
``$ref`` pointers (a remote reference would need a network fetch on a document
that may be attacker-supplied), refuses documents above a size limit, and
returns plain dataclasses so the API, the CLI and the tests share one code path.

What the inventory is *not*: a probe. Nothing here sends a request, so importing
a document does not need the authorization gate. Applying the declared servers
to a session scope is a deliberate, separate opt-in.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import yaml

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_OPERATIONS = 5000
MAX_REF_DEPTH = 8

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
WRITE_METHODS = frozenset({"post", "put", "patch", "delete"})


class OpenAPIImportError(ValueError):
    """The document cannot be imported: malformed, not OpenAPI, or too large."""


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str
    required: bool = False
    schema_type: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "in": self.location,
            "required": self.required,
            "type": self.schema_type,
        }


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    operation_id: str | None = None
    summary: str | None = None
    parameters: tuple[Parameter, ...] = ()
    content_types: tuple[str, ...] = ()
    security: tuple[str, ...] = ()
    deprecated: bool = False

    @property
    def authenticated(self) -> bool:
        return bool(self.security)

    def to_dict(self, base_url: str = "") -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "url": f"{base_url}{self.path}" if base_url else self.path,
            "operation_id": self.operation_id,
            "summary": self.summary,
            "parameters": [p.to_dict() for p in self.parameters],
            "content_types": list(self.content_types),
            "security": list(self.security),
            "authenticated": self.authenticated,
            "deprecated": self.deprecated,
        }


@dataclass(frozen=True)
class OpenAPIDocument:
    spec_version: str
    title: str
    api_version: str
    servers: tuple[str, ...]
    operations: tuple[Operation, ...]
    truncated: bool = False
    declared_operations: int = 0


def _resolve(node: Any, root: dict, depth: int = 0) -> Any:
    """Follow a local ``$ref`` pointer; reject remote ones."""
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return node
    if depth >= MAX_REF_DEPTH:
        raise OpenAPIImportError(f"$ref chain too deep at {ref!r}")
    if not ref.startswith("#/"):
        raise OpenAPIImportError(
            f"external $ref is not supported ({ref!r}): resolve the document first"
        )
    target: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            raise OpenAPIImportError(f"unresolvable $ref: {ref}")
        target = target[part]
    return _resolve(target, root, depth + 1)


def _load(text: str) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise OpenAPIImportError("the document is empty")
    if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise OpenAPIImportError(
            f"the document is larger than {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB"
        )
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise OpenAPIImportError(f"not valid JSON or YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise OpenAPIImportError("the document is not a mapping")
    return loaded


def _version(root: dict) -> tuple[str, int]:
    if "openapi" in root:
        version = str(root.get("openapi") or "").strip()
        if not version:
            raise OpenAPIImportError("empty 'openapi' version")
        if not version.startswith("3"):
            raise OpenAPIImportError(f"unsupported OpenAPI version: {version}")
        return version, 3
    if str(root.get("swagger") or "").strip() != "2.0":
        raise OpenAPIImportError(
            "missing a version field: expected 'openapi' (3.x) or 'swagger': '2.0'"
        )
    return "2.0", 2


def _servers_v3(root: dict) -> tuple[str, ...]:
    urls: list[str] = []
    for entry in root.get("servers") or []:
        server = _resolve(entry, root)
        if not isinstance(server, dict):
            continue
        url = str(server.get("url") or "").strip()
        if not url:
            continue
        for name, variable in (server.get("variables") or {}).items():
            if not isinstance(variable, dict):
                continue
            default = variable.get("default")
            if default is None:
                continue
            url = url.replace("{" + str(name) + "}", str(default))
        urls.append(url.rstrip("/"))
    return tuple(urls)


def _servers_v2(root: dict) -> tuple[str, ...]:
    host = str(root.get("host") or "").strip()
    if not host:
        return ()
    base = str(root.get("basePath") or "").strip()
    schemes = [str(s) for s in (root.get("schemes") or ["https"])]
    return tuple(f"{scheme}://{host}{base}".rstrip("/") for scheme in schemes)


def _parameters(raw: Any, root: dict) -> list[Parameter]:
    parsed: list[Parameter] = []
    for entry in raw or []:
        entry = _resolve(entry, root)
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        location = str(entry.get("in") or "").strip().lower()
        if not name or not location:
            continue
        schema = _resolve(entry.get("schema") or {}, root)
        schema_type = schema.get("type") if isinstance(schema, dict) else None
        if not schema_type:
            # Swagger 2.0 declares the type inline instead of under ``schema``.
            schema_type = entry.get("type")
        parsed.append(
            Parameter(
                name=name,
                location=location,
                required=bool(entry.get("required")),
                schema_type=str(schema_type) if schema_type else None,
            )
        )
    return parsed


def _merge_parameters(shared: list[Parameter], own: list[Parameter]) -> tuple[Parameter, ...]:
    merged: dict[tuple[str, str], Parameter] = {(p.name, p.location): p for p in shared}
    for param in own:
        merged[(param.name, param.location)] = param
    return tuple(merged.values())


def _content_types(op: dict, root: dict, major: int, parameters: list[Parameter]) -> tuple[str, ...]:
    if major == 3:
        body = _resolve(op.get("requestBody") or {}, root)
        if not isinstance(body, dict):
            return ()
        return tuple(str(name) for name in (body.get("content") or {}))
    # ``location`` is normalised to lower case when the parameter is parsed.
    if not any(p.location in ("body", "formdata") for p in parameters):
        return ()
    declared = op.get("consumes") or root.get("consumes") or []
    return tuple(str(name) for name in declared)


def _security(op: dict, root: dict) -> tuple[str, ...]:
    raw = op.get("security", None)
    if raw is None:
        raw = root.get("security") or []
    names: set[str] = set()
    for requirement in raw or []:
        requirement = _resolve(requirement, root)
        if isinstance(requirement, dict):
            names.update(str(name) for name in requirement)
    return tuple(sorted(names))


def _operations(root: dict, major: int) -> tuple[list[Operation], int]:
    paths = _resolve(root.get("paths") or {}, root)
    if not isinstance(paths, dict):
        raise OpenAPIImportError("'paths' is not a mapping")
    operations: list[Operation] = []
    for path, raw_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        item = _resolve(raw_item, root)
        if not isinstance(item, dict):
            continue
        shared = _parameters(item.get("parameters"), root)
        for method, raw_op in item.items():
            name = str(method).lower()
            if name not in HTTP_METHODS:
                continue
            op = _resolve(raw_op, root)
            if not isinstance(op, dict):
                continue
            parameters = _merge_parameters(shared, _parameters(op.get("parameters"), root))
            operations.append(
                Operation(
                    method=name,
                    path=path,
                    operation_id=str(op["operationId"]) if op.get("operationId") else None,
                    summary=str(op["summary"]) if op.get("summary") else None,
                    parameters=parameters,
                    content_types=_content_types(op, root, major, list(parameters)),
                    security=_security(op, root),
                    deprecated=bool(op.get("deprecated")),
                )
            )
    operations.sort(key=lambda op: (op.path, op.method))
    return operations, len(operations)


def parse_document(text: str) -> OpenAPIDocument:
    """Parse a JSON or YAML OpenAPI document into an inventory-shaped object."""
    root = _load(text)
    spec_version, major = _version(root)
    servers = _servers_v3(root) if major == 3 else _servers_v2(root)
    operations, declared = _operations(root, major)
    truncated = declared > MAX_OPERATIONS
    if truncated:
        operations = operations[:MAX_OPERATIONS]
    info = root.get("info") if isinstance(root.get("info"), dict) else {}
    return OpenAPIDocument(
        spec_version=spec_version,
        title=str(info.get("title") or "") or "untitled",
        api_version=str(info.get("version") or ""),
        servers=servers,
        operations=tuple(operations),
        truncated=truncated,
        declared_operations=declared,
    )


def contract_warnings(doc: OpenAPIDocument) -> list[dict]:
    """Issues visible in the document itself, before any request is sent."""
    warnings: list[dict] = []

    def add(severity: str, code: str, message: str, method: str | None = None, path: str | None = None) -> None:
        warnings.append(
            {"severity": severity, "code": code, "message": message, "method": method, "path": path}
        )

    if not doc.operations:
        add("medium", "no_operations", "The document declares no operations.")
    if doc.truncated:
        add(
            "low",
            "operations_truncated",
            f"Only the first {MAX_OPERATIONS} of {doc.declared_operations} operations were imported.",
        )
    if not doc.servers:
        add("info", "no_servers", "No server is declared: URLs stay relative to the document.")
    for server in doc.servers:
        if urlparse(server).scheme == "http":
            add("medium", "plaintext_server", f"Server {server} is plain HTTP.")

    for op in doc.operations:
        if op.deprecated:
            add(
                "info",
                "deprecated_operation",
                f"{op.method.upper()} {op.path} is marked deprecated but still listed.",
                op.method,
                op.path,
            )
        if not op.security:
            severity = "medium" if op.method in WRITE_METHODS else "low"
            add(
                severity,
                "unauthenticated_operation",
                f"{op.method.upper()} {op.path} declares no security requirement.",
                op.method,
                op.path,
            )
        untyped = sorted(p.name for p in op.parameters if not p.schema_type and p.location != "path")
        if untyped:
            shown = ", ".join(untyped[:5])
            add(
                "low",
                "untyped_parameter",
                f"{op.method.upper()} {op.path}: no schema type for {shown}"
                + (" ..." if len(untyped) > 5 else ""),
                op.method,
                op.path,
            )
    return warnings


def inventory(doc: OpenAPIDocument) -> dict:
    """JSON-ready inventory: spec metadata, servers, endpoints, warnings."""
    base_url = doc.servers[0] if doc.servers else ""
    method_counts: dict[str, int] = {}
    endpoints = []
    for op in doc.operations:
        method_counts[op.method] = method_counts.get(op.method, 0) + 1
        endpoints.append(op.to_dict(base_url))
    return {
        "spec": {
            "version": doc.spec_version,
            "title": doc.title,
            "api_version": doc.api_version,
        },
        "servers": list(doc.servers),
        "endpoint_count": len(endpoints),
        "method_counts": method_counts,
        "endpoints": endpoints,
        "warnings": contract_warnings(doc),
    }


def server_hosts(servers: tuple[str, ...]) -> list[str]:
    """Host names from ``servers``, for building a session scope rule set."""
    hosts: list[str] = []
    for server in servers:
        host = urlparse(server).hostname
        if host and host not in hosts:
            hosts.append(host)
    return hosts
