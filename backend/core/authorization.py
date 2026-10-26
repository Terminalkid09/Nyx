"""One authorization check for every outbound active probe.

Two independent gates, both fail-closed:

1. **Session scope** — the include/exclude rules the user configured for the
   session that produced the request.
2. **Rules of Engagement** — active, correctly signed profiles (F-01).

With no scope rules and no RoE profiles, both gates allow (the desktop
workflow); with any rule or profile configured, a probe must satisfy it.
"""
import uuid

from core.roe import authorize_url
from core.scope import is_url_in_scope


def _as_uuid(value):
    """Accept the UUID objects routes get from the DB and the strings they
    receive from API bodies. The scope query binds a UUID column, so passing a
    raw string raised ``'str' object has no attribute 'hex'`` and turned every
    gated job into an error instead of a decision."""
    if value is None or isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


async def authorize(
    session_id, url: str
) -> tuple[bool, str | None, str | None]:
    """Return (allowed, kind, detail) where kind is "out_of_scope"/"roe"."""
    raw_session = session_id
    session_id = _as_uuid(session_id)
    if raw_session is not None and session_id is None:
        # A malformed session id must not silently degrade to "no scope rules":
        # that would turn a typo into an unscoped engagement.
        return False, "invalid_session", str(raw_session)
    if session_id is not None:
        in_scope, rule_name = await is_url_in_scope(session_id, url)
        if not in_scope:
            return False, "out_of_scope", rule_name

    allowed, reason = await authorize_url(url)
    if not allowed:
        return False, "roe", reason
    return True, None, None
