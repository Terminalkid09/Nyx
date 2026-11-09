"""Build reproducible evidence for a finding.

A finding that only says "parameter id is injectable" forces the tester to
search the proxy history to reproduce it. Storing a curl command (and a short
response excerpt) with the finding keeps the proof attached to the result.
"""
import shlex

_MAX_BODY = 4096

_SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-api-key",
    "proxy-authorization", "x-auth-token", "x-csrf-token",
}


def request_fields(event: dict) -> tuple[str, str, dict, str | None]:
    """Normalise the two event shapes used by passive and active scanners."""
    event = event or {}
    method = str(event.get("method") or "GET")
    url = str(event.get("url") or "")
    headers = event.get("request_headers") or event.get("headers") or {}
    if "request_body" in event:
        body = event.get("request_body")
    else:
        body = event.get("body")
    if not isinstance(headers, dict):
        headers = {}
    return method, url, headers, body


def build_curl(event: dict) -> str | None:
    """Return a POSIX curl command reproducing the request, or None."""
    method, url, headers, body = request_fields(event)
    if not url.startswith(("http://", "https://")):
        return None
    parts = ["curl -i", "-X", shlex.quote(method), shlex.quote(url)]
    for key, value in headers.items():
        key_lower = str(key).lower()
        if key_lower in ("host", "content-length"):
            continue
        # Evidence ends up in reports that are shared with clients: never copy
        # live credentials into it. The tester can re-add their own token.
        if key_lower in _SENSITIVE_HEADERS:
            value = "[REDACTED]"
        parts.extend(["-H", shlex.quote(f"{key}: {value}")])
    if body:
        text = str(body)
        if len(text) > _MAX_BODY:
            text = text[:_MAX_BODY]
        parts.extend(["--data-raw", shlex.quote(text)])
    return " ".join(parts)


def build_response_excerpt(event: dict) -> str | None:
    event = event or {}
    status = event.get("status") or event.get("response_status")
    body = event.get("body") if "status" in event else event.get("response_body")
    if status is None and not body:
        return None
    lines = []
    if status is not None:
        lines.append(f"# response: {status}")
    if body:
        text = str(body)
        if len(text) > _MAX_BODY:
            text = text[:_MAX_BODY] + "\n… (truncated)"
        lines.append(text)
    return "\n".join(lines) if lines else None


def build_evidence(result, event: dict) -> str | None:
    """Combine the check's own evidence with the replayable request."""
    parts = []
    existing = getattr(result, "evidence", None)
    if existing:
        parts.append(str(existing))
    curl = build_curl(event)
    if curl:
        parts.append("Reproduce:\n" + curl)
    excerpt = build_response_excerpt(event)
    if excerpt:
        parts.append(excerpt)
    return "\n\n".join(parts) if parts else None
