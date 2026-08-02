import asyncio
import uuid
import re
import threading
import logging
from datetime import datetime, timezone

from mitmproxy import http
from sqlalchemy import select

from core.events.bus import EventBus
from core.storage.models import InterceptorRule, InterceptedItem
from core.storage.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class InterceptorEngine:
    """Intercepts and pauses matching HTTP flows based on configurable rules."""
    def __init__(self, event_bus: EventBus, proxy_engine):
        """Initialise the interceptor with event bus and proxy engine reference."""
        self.event_bus = event_bus
        self.proxy_engine = proxy_engine
        self.enabled = False
        self._lock = threading.Lock()
        self._paused_flows: dict[str, http.HTTPFlow] = {}
        self.paused_items: dict[str, dict] = {}
        self._mitmproxy_loop: asyncio.AbstractEventLoop | None = None
        self._rules_cache: list[dict] = []
        self._cache_lock = threading.Lock()

    # --- mitmproxy addon hooks ---

    def request(self, flow: http.HTTPFlow):
        """mitmproxy hook called on each request — checks interception rules."""
        if not self.enabled:
            return
        if self._mitmproxy_loop is None:
            self._mitmproxy_loop = asyncio.get_event_loop()
        self._check_flow(flow, "request")

    def response(self, flow: http.HTTPFlow):
        """mitmproxy hook called on each response — checks interception rules."""
        if not self.enabled:
            return
        if self._mitmproxy_loop is None:
            self._mitmproxy_loop = asyncio.get_event_loop()
        self._check_flow(flow, "response")

    # --- core interception logic ---

    def _check_flow(self, flow: http.HTTPFlow, direction: str):
        """Evaluate all cached rules against a flow and pause if a rule matches."""
        rules = self._get_cached_rules(direction)
        for rule in rules:
            if self._match_rule(flow, rule, direction):
                if rule["intercept_on_match"]:
                    item_id = str(uuid.uuid4())
                    flow.intercept()
                    flow.metadata["intercepted"] = True

                    snapshot = {
                        "method": flow.request.method,
                        "url": flow.request.pretty_url,
                        "headers": dict(flow.request.headers),
                        "body": self._safe_decode(flow.request.content),
                        "host": flow.request.pretty_host,
                        "path": flow.request.path,
                        "http_version": flow.request.http_version,
                    }
                    if direction == "response":
                        if flow.response is not None:
                            snapshot["status_code"] = flow.response.status_code
                            snapshot["reason"] = flow.response.reason
                            snapshot["response_headers"] = dict(flow.response.headers)
                            snapshot["response_body"] = self._safe_decode(flow.response.content)
                        else:
                            snapshot["status_code"] = None

                    item_info = {
                        "id": item_id,
                        "direction": direction,
                        "status": "paused",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        **snapshot,
                    }
                    with self._lock:
                        self._paused_flows[item_id] = flow
                        self.paused_items[item_id] = item_info

                    if self.proxy_engine and self.proxy_engine.fastapi_loop:
                        future = asyncio.run_coroutine_threadsafe(
                            self._db_save_intercepted(item_id, flow, direction),
                            self.proxy_engine.fastapi_loop,
                        )
                        future.add_done_callback(
                            lambda f: logger.error("DB save failed: %s", f.exception()) if f.exception() else None
                        )
                break

    async def _db_save_intercepted(self, item_id: str, flow: http.HTTPFlow, direction: str):
        """Persist an intercepted item to the database and publish a paused event."""
        request_id = flow.metadata.get("nyx_request_id")
        async with AsyncSessionLocal() as db:
            item = InterceptedItem(
                id=uuid.UUID(item_id),
                request_id=uuid.UUID(request_id) if request_id else uuid.uuid4(),
                direction=direction,
                status="paused",
            )
            db.add(item)
            await db.commit()

        await self.event_bus.publish({
            "type": f"interceptor.{direction}.paused",
            "item_id": item_id,
            "request_id": request_id,
            "direction": direction,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
        })

    def _get_cached_rules(self, direction: str) -> list[dict]:
        """Return enabled rules cached for the given direction scope."""
        with self._cache_lock:
            return [
                r for r in self._rules_cache
                if r["enabled"] and r["scope"] in (direction, "both")
            ]

    async def ensure_default_rules(self):
        """Create default catch-all rules if no interceptor rules exist."""
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(InterceptorRule).limit(1))
            if result.scalar_one_or_none() is not None:
                return
            defaults = [
                InterceptorRule(
                    name="Intercept all requests",
                    scope="request",
                    intercept_on_match=True,
                    match_type="url",
                    match_pattern=".*",
                    is_regex=True,
                    enabled=True,
                    order=0,
                ),
                InterceptorRule(
                    name="Intercept all responses",
                    scope="response",
                    intercept_on_match=True,
                    match_type="url",
                    match_pattern=".*",
                    is_regex=True,
                    enabled=False,
                    order=1,
                ),
            ]
            for rule in defaults:
                db.add(rule)
            await db.commit()
            logger.info("Created %d default interceptor rules", len(defaults))

    async def refresh_rules_cache(self):
        """Reload interception rules from the database into memory."""
        await self.ensure_default_rules()
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(InterceptorRule).order_by(InterceptorRule.order)
            )
            rules = result.scalars().all()
            with self._cache_lock:
                self._rules_cache = [
                    {
                        "id": str(r.id),
                        "enabled": r.enabled,
                        "scope": r.scope,
                        "intercept_on_match": r.intercept_on_match,
                        "match_type": r.match_type,
                        "match_pattern": r.match_pattern,
                        "is_regex": r.is_regex,
                        "order": r.order,
                    }
                    for r in rules
                ]

    def _match_rule(self, flow: http.HTTPFlow, rule: dict, direction: str) -> bool:
        """Check whether a flow matches a single rule's pattern."""
        match_type = rule.get("match_type")
        pattern = rule.get("match_pattern")
        if not pattern:
            return False

        if match_type == "url":
            text = flow.request.pretty_url
        elif match_type == "host":
            text = flow.request.pretty_host
        elif match_type == "path":
            text = flow.request.path
        elif match_type == "method":
            text = flow.request.method
        elif match_type == "body":
            text = self._safe_decode(flow.request.content) or ""
        elif match_type == "status" and flow.response:
            text = str(flow.response.status_code)
        elif match_type == "header":
            text = str(dict(flow.request.headers))
        elif match_type == "request_header":
            text = str(dict(flow.request.headers))
        elif match_type == "response_header" and flow.response:
            text = str(dict(flow.response.headers))
        elif match_type == "cookie":
            text = flow.request.headers.get("cookie", "")
        else:
            text = flow.request.pretty_url if direction == "request" else (
                str(flow.response.status_code) if flow.response else ""
            )

        if rule.get("is_regex"):
            try:
                return bool(re.search(pattern, text))
            except re.error:
                return False
        return pattern.lower() in text.lower()

    def _safe_decode(self, content: bytes | None) -> str | None:
        """Decode bytes to UTF-8, falling back to hex on failure."""
        if not content:
            return None
        try:
            return content.decode("utf-8", errors="replace")
        except Exception:
            return content.hex()

    def clear_paused_flows(self):
        """Kill all paused flows and clear internal state (called before proxy stop/switch)."""
        with self._lock:
            for flow in self._paused_flows.values():
                try:
                    if self._mitmproxy_loop:
                        self._mitmproxy_loop.call_soon_threadsafe(flow.kill)
                except Exception:
                    pass
            self._paused_flows.clear()
            self.paused_items.clear()

    # --- API-facing methods ---

    async def forward_item(self, item_id: str, modifications: dict | None = None):
        """Apply optional modifications to a paused flow and resume it."""
        with self._lock:
            flow = self._paused_flows.pop(item_id, None)

        if not flow:
            raise ValueError("Item not found or already handled")

        if modifications:
            if "method" in modifications:
                flow.request.method = modifications["method"]
            if "url" in modifications:
                flow.request.url = modifications["url"]
            if "headers" in modifications and isinstance(modifications["headers"], dict):
                flow.request.headers.clear()
                for k, v in modifications["headers"].items():
                    flow.request.headers[k] = str(v)
            if "body" in modifications:
                body_bytes = modifications["body"]
                if isinstance(body_bytes, str):
                    body_bytes = body_bytes.encode("utf-8")
                flow.request.content = body_bytes

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(InterceptedItem).where(InterceptedItem.id == uuid.UUID(item_id))
            )
            item = result.scalar_one_or_none()
            if item:
                if modifications:
                    item.modified_method = modifications.get("method")
                    item.modified_url = modifications.get("url")
                    item.modified_headers = modifications.get("headers")
                    item.modified_body = modifications.get("body")
                item.status = "forwarded"
                item.action = "forwarded"
                await db.commit()

        with self._lock:
            self.paused_items.pop(item_id, None)

        if self._mitmproxy_loop:
            self._mitmproxy_loop.call_soon_threadsafe(flow.resume)

        await self.event_bus.publish({
            "type": "interceptor.item.forwarded",
            "item_id": item_id,
        })

    async def drop_item(self, item_id: str):
        """Kill a paused flow without forwarding it."""
        with self._lock:
            flow = self._paused_flows.pop(item_id, None)

        if not flow:
            raise ValueError("Item not found or already handled")

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(InterceptedItem).where(InterceptedItem.id == uuid.UUID(item_id))
            )
            item = result.scalar_one_or_none()
            if item:
                item.status = "dropped"
                item.action = "dropped"
                await db.commit()

        with self._lock:
            self.paused_items.pop(item_id, None)

        if self._mitmproxy_loop:
            self._mitmproxy_loop.call_soon_threadsafe(flow.kill)

        await self.event_bus.publish({
            "type": "interceptor.item.dropped",
            "item_id": item_id,
        })

    def pause_intercept(self):
        """Temporarily stop intercepting new flows."""
        self.enabled = False

    def resume_intercept(self):
        """Resume intercepting new flows."""
        self.enabled = True

    def get_paused(self) -> list[dict]:
        """Return a snapshot of all currently paused items."""
        with self._lock:
            return list(self.paused_items.values())
