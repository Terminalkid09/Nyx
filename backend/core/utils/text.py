"""Shared body-decoding and content-type classification helpers.

Consolidates the ``_safe_decode`` / ``_is_text_content`` implementations that
were duplicated across the proxy logger, the interceptor and the
match/replace engine.
"""

# Content types whose bodies are treated as decodable text. Anything else is
# represented as hex so binary payloads never corrupt storage or the UI.
TEXT_CONTENT_TYPES = {
    "application/json", "application/xml", "application/xhtml+xml",
    "application/javascript", "application/x-javascript", "application/ecmascript",
    "application/graphql", "application/ld+json", "application/soap+xml",
}


def content_type_base(content_type: str | None) -> str:
    """Normalize a Content-Type header to its lowercase base type (no params)."""
    if not content_type:
        return ""
    return content_type.lower().split(";")[0].strip()


def is_text_content(content_type: str | None) -> bool:
    """True when bodies with this Content-Type should be handled as text.

    An empty/missing Content-Type is treated as text (best-effort decode).
    """
    ct = content_type_base(content_type)
    if not ct:
        return True
    return ct.startswith("text/") or ct in TEXT_CONTENT_TYPES


def safe_decode(
    content: bytes | None,
    content_type: str = "",
    hex_limit: int | None = 50 * 1024,
) -> str | None:
    """Decode response/request body bytes to a string.

    - ``None``/empty → ``None``
    - known-text (or unspecified) content types → UTF-8 with replacement chars
    - non-text or undecodable bodies → hex string, truncated to ``hex_limit``
      bytes before conversion (``None`` disables truncation)
    """
    if not content:
        return None

    def _hex() -> str:
        data = content[:hex_limit] if hex_limit is not None else content
        return data.hex()

    if content_type and not is_text_content(content_type):
        return _hex()
    try:
        return content.decode("utf-8", errors="replace")
    except Exception:
        return _hex()
