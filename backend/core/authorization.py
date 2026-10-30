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
    session_id, url: str, *, require_session: bool = False
) -> tuple[bool, str | None, str | None]:
    """Return (allowed, kind, detail) where kind is "out_of_scope"/"roe".

    ``require_session`` is the fail-closed mode used by every HTTP endpoint
    that launches an active probe. Without it, omitting ``session_id`` skipped
    the session scope rules entirely: a URL excluded by the engagement the
    operator was working in could be scanned through any unrestricted session
    (or none at all). Internal callers such as the CLI keep the permissive
    default because they have no session context and are already governed by
    the Rules of Engagement.
    """
    raw_session = session_id
    session_id = _as_uuid(session_id)
    if raw_session is None:
        if require_session:
            return False, "missing_session", "session_id is required for active probes"
    elif session_id is None:
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
