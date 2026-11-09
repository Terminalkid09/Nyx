"""Import external API descriptions into an endpoint inventory.

OpenAPI comes first because it is cheap and it buys a lot: the document already
declares every path, method, parameter and security requirement, so Nyx can
build an inventory and a contract review without touching the target at all.
Burp Suite item exports are read into the same shape by ``burp.py``; a ZAP
session export is still open (its format is a database, not a flat document).
"""
from modules.importer.burp import BurpDocument, BurpImportError
from modules.importer.burp import parse_document as parse_burp_document
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
    "BurpDocument",
    "BurpImportError",
    "parse_burp_document",
    "Operation",
    "Parameter",
    "contract_warnings",
    "inventory",
    "parse_document",
]
