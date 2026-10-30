"""Import a Burp Suite XML export into an endpoint inventory.

Nyx could already *export* to other tools but not read their history back, so a
tester moving from Burp had to re-crawl a target they had already mapped. The
export lists every request Burp saw; deduplicating it by (method, path) gives
the same endpoint inventory the OpenAPI importer produces, which lets the UI
reuse one table and the scanner start from real, observed endpoints.

Security: the document is attacker-influenced (a client can hand you their
export). ``xml.etree`` expands internal entities, so a doctype-declared
"billion laughs" payload would be a local DoS; Burp exports never carry a
doctype, so rejecting one is both safe and lossless.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

MAX_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_ITEMS = 20_000


class BurpImportError(ValueError):
    """The document is not a Burp item export we can read."""


@dataclass
class BurpEndpoint:
    method: str
    path: str
    url: str
    host: str
    status: int | None
    mimetype: str | None
    query_parameters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "method": self.method.lower(),
            "path": self.path,
            "url": self.url,
            "operation_id": None,
            "summary": None,
            "parameters": [
                {"name": name, "in": "query", "required": False, "type": None}
                for name in self.query_parameters
            ],
            "content_types": [self.mimetype] if self.mimetype else [],
            "security": [],
            "authenticated": False,
            "status": self.status,
        }


@dataclass
class BurpDocument:
    endpoints: list[BurpEndpoint]
    hosts: list[str]
    item_count: int
    truncated: bool


def _text(item: ET.Element, tag: str) -> str | None:
    node = item.find(tag)
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    return value or None


def parse_document(text: str, *, max_items: int = MAX_ITEMS) -> BurpDocument:
    if len(text.encode("utf-8", errors="ignore")) > MAX_DOCUMENT_BYTES:
        raise BurpImportError(
            f"The document is larger than {MAX_DOCUMENT_BYTES // (1024 * 1024)} MB."
        )

    # Scan the whole document, not just the prolog: a caller can pad the file
    # with comments or whitespace and push a DOCTYPE past any fixed prefix
    # window. A Burp export never carries one anywhere, so a hit is a reject.
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise BurpImportError("The document declares a DOCTYPE/ENTITY, which a Burp export never contains.")

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise BurpImportError(f"Malformed XML: {exc}") from exc

    if root.tag.lower() != "items":
        raise BurpImportError(
            "This is not a Burp item export (expected an <items> root element)."
        )

    items = root.findall("item")
    if not items:
        raise BurpImportError("The export contains no <item> entries.")

    seen: dict[tuple[str, str], BurpEndpoint] = {}
    hosts: list[str] = []
    truncated = False

    for index, item in enumerate(items):
        if index >= max_items:
            truncated = True
            break

        method = (_text(item, "method") or "GET").upper()
        url = _text(item, "url")
        raw_path = _text(item, "path") or ""
        host = _text(item, "host") or ""
        protocol = (_text(item, "protocol") or "https").lower()

        if not url:
            if not host or not raw_path:
                continue
            url = f"{protocol}://{host}{raw_path}"

        split = urlsplit(url)
        if split.hostname:
            host = split.hostname
        path = split.path or "/"
        key = (method, path)

        if host and host not in hosts:
            hosts.append(host)

        if key in seen:
            continue

        mimetype = _text(item, "mimetype")
        status_text = _text(item, "status")
        try:
            status = int(status_text) if status_text else None
        except ValueError:
            status = None

        query_parameters: list[str] = []
        for name, _value in parse_qsl(split.query, keep_blank_values=True):
            if name not in query_parameters:
                query_parameters.append(name)

        seen[key] = BurpEndpoint(
            method=method,
            path=path,
            url=url,
            host=host,
            status=status,
            mimetype=mimetype if mimetype and mimetype != "null" else None,
            query_parameters=query_parameters,
        )

    if not seen:
        raise BurpImportError("No request in the export had a usable URL.")

    return BurpDocument(
        endpoints=list(seen.values()),
        hosts=hosts,
        item_count=len(items),
        truncated=truncated,
    )


def inventory(doc: BurpDocument, filename: str | None = None) -> dict:
    """Same JSON shape as the OpenAPI inventory, so one UI renders both."""
    method_counts: dict[str, int] = {}
    for endpoint in doc.endpoints:
        key = endpoint.method.lower()
        method_counts[key] = method_counts.get(key, 0) + 1

    warnings: list[dict] = []
    if doc.truncated:
        warnings.append(
            {
                "severity": "low",
                "code": "items_truncated",
                "message": f"Only the first {MAX_ITEMS} items of {doc.item_count} were imported.",
                "method": None,
                "path": None,
            }
        )
    for endpoint in doc.endpoints:
        if endpoint.url.startswith("http://"):
            warnings.append(
                {
                    "severity": "medium",
                    "code": "plaintext_server",
                    "message": f"{endpoint.method} {endpoint.path} was captured over plain HTTP.",
                    "method": endpoint.method.lower(),
                    "path": endpoint.path,
                }
            )

    title = Path(filename).stem if filename else "Burp export"
    return {
        "spec": {"version": "burp-xml", "title": title, "api_version": ""},
        "servers": list(doc.hosts),
        "endpoint_count": len(doc.endpoints),
        "method_counts": method_counts,
        "endpoints": [endpoint.to_dict() for endpoint in doc.endpoints],
        "warnings": warnings,
        "filename": Path(filename).name if filename else None,
        "item_count": doc.item_count,
    }
