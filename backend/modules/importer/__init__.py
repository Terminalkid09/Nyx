"""Import external API descriptions into an endpoint inventory.

OpenAPI comes first because it is cheap and it buys a lot: the document already
declares every path, method, parameter and security requirement, so Nyx can
build an inventory and a contract review without touching the target at all.
Burp/ZAP exports can be added behind the same shape.
"""
from modules.importer.openapi import (
    MAX_DOCUMENT_BYTES,
    OpenAPIDocument,
    OpenAPIImportError,
    Operation,
    Parameter,
    contract_warnings,
    inventory,
    parse_document,
)

__all__ = [
    "MAX_DOCUMENT_BYTES",
    "OpenAPIDocument",
    "OpenAPIImportError",
    "Operation",
    "Parameter",
    "contract_warnings",
    "inventory",
    "parse_document",
]
