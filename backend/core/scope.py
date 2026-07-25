import re
from urllib.parse import urlparse
from core.storage.models import TargetScopeRule


def get_url_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or url
    return host.lower()


def match_url(url: str, rule: TargetScopeRule) -> bool:
    if rule.is_regex:
        pattern = rule.pattern
        scope_domain = getattr(rule, 'match_domain', False)
        if scope_domain:
            domain = get_url_domain(url)
            return bool(re.search(pattern, domain))
        return bool(re.search(pattern, url))
    return rule.pattern in url


def check_scope(url: str, rules: list[TargetScopeRule]) -> tuple[bool, str | None, str | None]:
    enabled_rules = [r for r in rules if r.enabled]
    if not enabled_rules:
        return True, None, None

    includes = [r for r in enabled_rules if r.rule_type == "include"]
    excludes = [r for r in enabled_rules if r.rule_type == "exclude"]

    if includes and not excludes:
        for r in includes:
            if match_url(url, r):
                return True, r.name, "include"
        return False, None, None

    if excludes and not includes:
        for r in excludes:
            if match_url(url, r):
                return False, r.name, "exclude"
        return True, None, None

    if includes and excludes:
        matched_include = None
        for r in includes:
            if match_url(url, r):
                matched_include = r
                break
        if not matched_include:
            return False, None, None
        for r in excludes:
            if match_url(url, r):
                return False, r.name, "exclude"
        return True, matched_include.name, "include"

    return True, None, None


def make_scope_checker(session_id):
    from core.storage.database import AsyncSessionLocal
    from sqlalchemy import select

    async def is_in_scope(url: str) -> tuple[bool, str | None]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(TargetScopeRule).where(
                    TargetScopeRule.session_id == session_id
                ).order_by(TargetScopeRule.order)
            )
            rules = list(result.scalars().all())
            in_scope, rule_name, _ = check_scope(url, rules)
            return in_scope, rule_name

    return is_in_scope
