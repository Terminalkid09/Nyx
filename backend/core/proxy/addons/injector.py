import re
import time
import logging
from mitmproxy import http

logger = logging.getLogger(__name__)

TEXT_PREFIXES = ("text/", "application/json", "application/xml", "application/xhtml+xml",
                 "application/javascript", "application/x-javascript", "application/ecmascript",
                 "application/graphql", "application/ld+json", "application/soap+xml")


def _is_text_content(message) -> bool:
    ct = (message.headers.get("content-type") or "").lower().split(";")[0].strip()
    if ct.startswith("text/"):
        return True
    return ct in TEXT_PREFIXES


class InjectorAddon:
    def __init__(self, get_rules_fn=lambda: []):
        self._get_rules = get_rules_fn
        self._rules_cache: list = []
        self._cache_ts: float = 0
        self._cache_ttl: float = 30.0

    def _get_cached_rules(self) -> list:
        now = time.monotonic()
        if now - self._cache_ts > self._cache_ttl:
            self._rules_cache = self._get_rules()
            self._cache_ts = now
        return self._rules_cache

    def request(self, flow: http.HTTPFlow):
        for rule in self._get_cached_rules():
            if rule.get("scope") not in ("request", "both"):
                continue
            self._apply_rule(rule, flow.request)

    def response(self, flow: http.HTTPFlow):
        for rule in self._get_cached_rules():
            if rule.get("scope") not in ("response", "both"):
                continue
            self._apply_rule(rule, flow.response)

    def _apply_rule(self, rule, message):
        match_type = rule.get("match_type")
        if match_type == "header":
            for key, value in list(message.headers.items()):
                new_value = self._replace(rule, value)
                if new_value != value:
                    message.headers[key] = new_value
        elif match_type == "body" and message.content:
            if not _is_text_content(message):
                return
            body = message.content.decode("utf-8", errors="replace")
            new_body = self._replace(rule, body)
            if new_body != body:
                message.content = new_body.encode("utf-8")

    def _replace(self, rule, text: str) -> str:
        if rule.get("is_regex"):
            return re.sub(rule["match_pattern"], rule["replacement"], text)
        return text.replace(rule["match_pattern"], rule["replacement"])
