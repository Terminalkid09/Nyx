import re
import asyncio
import logging
from mitmproxy import http
from sqlalchemy import select

from core.events.bus import EventBus
from core.storage.database import AsyncSessionLocal
from core.storage.models import MatchReplaceRule

logger = logging.getLogger(__name__)

TEXT_CONTENT_TYPES = {
    "text/", "application/json", "application/xml", "application/xhtml+xml",
    "application/javascript", "application/x-javascript", "application/ecmascript",
    "application/graphql", "application/ld+json", "application/soap+xml",
}


def _is_text_content(content_type: str | None) -> bool:
    if not content_type:
        return True
    ct = content_type.lower().split(";")[0].strip()
    if ct.startswith("text/"):
        return True
    return ct in TEXT_CONTENT_TYPES


class MatchReplaceEngine:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._rules: list[MatchReplaceRule] = []
        self._refresh_task: asyncio.Task | None = None

    def start_refresh_task(self):
        self._refresh_task = asyncio.create_task(self._periodic_refresh())

    async def stop_refresh_task(self):
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
            self._refresh_task = None

    async def _periodic_refresh(self):
        while True:
            try:
                await asyncio.sleep(30)
                await self.refresh_rules()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Periodic refresh error: %s", e)

    def request(self, flow: http.HTTPFlow):
        self.apply_rules_to_flow(flow, is_request=True)

    def response(self, flow: http.HTTPFlow):
        self.apply_rules_to_flow(flow, is_request=False)

    async def refresh_rules(self):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(MatchReplaceRule)
                .where(MatchReplaceRule.enabled == True)
                .order_by(MatchReplaceRule.order)
            )
            self._rules = list(result.scalars().all())

    def apply_rules_to_flow(self, flow: http.HTTPFlow, is_request: bool = True):
        for rule in self._rules:
            scope = rule.scope
            if is_request and scope not in ("request", "request_header", "request_body"):
                continue
            if not is_request and scope not in ("response", "response_header", "response_body"):
                continue
            try:
                self._apply_rule(flow, rule)
            except Exception as e:
                logger.error("Error applying rule %s: %s", rule.name, e)

    def _apply_rule(self, flow: http.HTTPFlow, rule: MatchReplaceRule):
        pattern = rule.match_pattern
        replacement = rule.replacement
        if not pattern:
            return

        if rule.is_regex:
            def replacer(text: str) -> str:
                try:
                    return re.sub(pattern, replacement, text)
                except re.error:
                    return text
        else:
            def replacer(text: str) -> str:
                return text.replace(pattern, replacement)

        scope = rule.scope

        if scope in ("request", "request_header", "response", "response_header"):
            headers = flow.request.headers if scope.startswith("request") else flow.response.headers
            for key in list(headers.keys()):
                old = headers[key]
                new = replacer(old)
                if new != old:
                    headers[key] = new

        if scope in ("request", "request_body"):
            if flow.request.content:
                ct = flow.request.headers.get("content-type", "")
                if not _is_text_content(ct):
                    return
                try:
                    text = flow.request.content.decode("utf-8", errors="replace")
                    new_text = replacer(text)
                    if new_text != text:
                        flow.request.content = new_text.encode("utf-8")
                except Exception:
                    pass
        elif scope in ("response", "response_body"):
            if flow.response and flow.response.content:
                ct = flow.response.headers.get("content-type", "")
                if not _is_text_content(ct):
                    return
                try:
                    text = flow.response.content.decode("utf-8", errors="replace")
                    new_text = replacer(text)
                    if new_text != text:
                        flow.response.content = new_text.encode("utf-8")
                except Exception:
                    pass

        if scope == "request":
            url = flow.request.pretty_url
            new_url = replacer(url)
            if new_url != url:
                flow.request.url = new_url
