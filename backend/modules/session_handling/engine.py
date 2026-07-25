import asyncio
import re
import uuid
import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import select, delete

from core.events.bus import EventBus
from core.storage.models import CookieJar, SessionHandlingRule
from core.storage.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class CookieJarEngine:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._rules_cache: list[dict] = []
        self._cache_lock = asyncio.Lock()
        self._scope_include: list[re.Pattern] = []
        self._scope_exclude: list[re.Pattern] = []

    async def start(self):
        self.event_bus.subscribe("response.received", self._on_response_received)
        await self._refresh_rules()
        self.event_bus.subscribe("target.scope.updated", self._on_scope_updated)

    async def stop(self):
        self.event_bus.unsubscribe("response.received", self._on_response_received)
        self.event_bus.unsubscribe("target.scope.updated", self._on_scope_updated)

    async def _on_scope_updated(self, event: dict):
        self._scope_include = [re.compile(p, re.I) for p in event.get("include", [])]
        self._scope_exclude = [re.compile(p, re.I) for p in event.get("exclude", [])]

    def _is_in_scope(self, domain: str) -> bool:
        if not self._scope_include:
            return True
        if any(p.search(domain) for p in self._scope_exclude):
            return False
        return any(p.search(domain) for p in self._scope_include)

    async def _on_response_received(self, event: dict):
        headers = event.get("headers", {})
        set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
        if not set_cookie:
            return

        session_id = event.get("session_id")
        if not session_id:
            return

        cookies = self._parse_set_cookie(set_cookie)
        async with AsyncSessionLocal() as db:
            for cookie_data in cookies:
                domain = cookie_data.get("domain", "")
                if not self._is_in_scope(domain):
                    logger.debug("Cookie %s for %s outside scope, skipping", cookie_data["name"], domain)
                    continue
                existing = await db.execute(
                    select(CookieJar).where(
                        CookieJar.session_id == uuid.UUID(session_id),
                        CookieJar.domain == domain,
                        CookieJar.name == cookie_data["name"],
                        CookieJar.path == cookie_data.get("path", "/"),
                    )
                )
                if existing.scalar_one_or_none():
                    await db.execute(
                        delete(CookieJar).where(
                            CookieJar.session_id == uuid.UUID(session_id),
                            CookieJar.domain == domain,
                            CookieJar.name == cookie_data["name"],
                            CookieJar.path == cookie_data.get("path", "/"),
                        )
                    )
                cookie = CookieJar(
                    session_id=uuid.UUID(session_id),
                    domain=domain,
                    name=cookie_data["name"],
                    value=cookie_data["value"],
                    path=cookie_data.get("path", "/"),
                    secure=cookie_data.get("secure", False),
                    http_only=cookie_data.get("http_only", False),
                    same_site=cookie_data.get("same_site"),
                    expires=cookie_data.get("expires"),
                )
                db.add(cookie)
            await db.commit()

        logger.debug("Stored %d cookies from response", len(cookies))

    def _parse_set_cookie(self, header_value: str) -> list[dict]:
        cookies = []
        if isinstance(header_value, list):
            items = header_value
        else:
            items = [header_value]

        for item in items:
            parts = item.split(";")
            if not parts:
                continue
            name_value = parts[0].strip()
            if "=" not in name_value:
                continue
            name, value = name_value.split("=", 1)
            cookie = {
                "name": name.strip(),
                "value": value.strip(),
                "path": "/",
                "secure": False,
                "http_only": False,
                "same_site": None,
                "expires": None,
            }
            for attr in parts[1:]:
                attr = attr.strip()
                if attr.lower().startswith("path="):
                    cookie["path"] = attr.split("=", 1)[1].strip()
                elif attr.lower() == "secure":
                    cookie["secure"] = True
                elif attr.lower() == "httponly":
                    cookie["http_only"] = True
                elif attr.lower().startswith("domain="):
                    cookie["domain"] = attr.split("=", 1)[1].strip()
                elif attr.lower().startswith("samesite="):
                    cookie["same_site"] = attr.split("=", 1)[1].strip()
                elif attr.lower().startswith("expires="):
                    try:
                        cookie["expires"] = datetime.strptime(
                            attr.split("=", 1)[1].strip(),
                            "%a, %d %b %Y %H:%M:%S %Z",
                        ).replace(tzinfo=timezone.utc)
                    except (ValueError, IndexError):
                        pass
            cookies.append(cookie)
        return cookies

    async def get_cookies_for_url(self, url: str) -> list[dict]:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or "/"

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(CookieJar).where(
                    CookieJar.domain == domain,
                    CookieJar.path <= path,
                ).order_by(CookieJar.path.desc())
            )
            cookies = []
            now = datetime.now(timezone.utc)
            for c in result.scalars().all():
                if c.expires and c.expires < now:
                    continue
                cookies.append({
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                    "http_only": c.http_only,
                })
            return cookies

    async def inject_cookies(self, request_data: dict) -> dict:
        url = request_data.get("url", "")
        headers = dict(request_data.get("headers", {}))

        cookies = await self.get_cookies_for_url(url)
        if cookies:
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            existing = headers.get("Cookie", headers.get("cookie"))
            if existing:
                cookie_str = f"{existing}; {cookie_str}"
            headers["Cookie"] = cookie_str

        return {**request_data, "headers": headers}

    async def _refresh_rules(self):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SessionHandlingRule).where(
                    SessionHandlingRule.enabled == True,
                    SessionHandlingRule.rule_type == "cookie_jar",
                )
            )
            async with self._cache_lock:
                self._rules_cache = [
                    {
                        "id": str(r.id),
                        "config": r.config,
                    }
                    for r in result.scalars().all()
                ]


class MacroEngine:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self._variables: dict[str, str] = {}
        self._saved_variables: dict[str, dict[str, str]] = {}

    def save_variables(self, name: str) -> dict[str, str]:
        self._saved_variables[name] = dict(self._variables)
        return self._variables

    def load_variables(self, name: str) -> dict[str, str] | None:
        snapshot = self._saved_variables.get(name)
        if snapshot is not None:
            self._variables.update(snapshot)
        return snapshot

    def list_saved_variables(self) -> list[str]:
        return list(self._saved_variables.keys())

    def get_all_variables(self) -> dict[str, str]:
        return dict(self._variables)

    def clear_variables(self):
        self._variables.clear()

    async def execute_macro(self, session_id: uuid.UUID, requests_config: list[dict]) -> list[dict]:
        results = []
        self._variables.clear()

        for i, req_config in enumerate(requests_config):
            method = req_config.get("method", "GET")
            url = self._substitute_vars(req_config.get("url", ""))
            headers = req_config.get("headers", {})
            body = req_config.get("body")

            substituted_headers = {}
            for k, v in headers.items():
                substituted_headers[k] = self._substitute_vars(str(v))

            if body:
                body = self._substitute_vars(body)

            import httpx
            try:
                async with httpx.AsyncClient(verify=False, timeout=30) as client:
                    resp = await client.request(
                        method=method,
                        url=url,
                        headers=substituted_headers,
                        content=body,
                    )

                result = {
                    "step": i,
                    "method": method,
                    "url": url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:10000],
                    "size": len(resp.content),
                }

                # Extract variables from response
                extractors = req_config.get("extract", {})
                for var_name, pattern in extractors.items():
                    try:
                        match = re.search(pattern, resp.text)
                        if match:
                            self._variables[var_name] = match.group(1) if match.lastindex else match.group(0)
                    except re.error:
                        pass

                results.append(result)

                # Check for failure conditions
                fail_on = req_config.get("fail_on")
                if fail_on and isinstance(fail_on, list):
                    for condition in fail_on:
                        if condition.get("type") == "status" and resp.status_code == condition.get("value"):
                            result["failed"] = True
                            result["reason"] = f"Status {resp.status_code} matched fail condition"
                            return results

            except Exception as e:
                results.append({
                    "step": i,
                    "method": method,
                    "url": url,
                    "error": str(e),
                    "failed": True,
                    "reason": str(e),
                })
                break

        return results

    def _substitute_vars(self, text: str) -> str:
        def replacer(match):
            var_name = match.group(1)
            return self._variables.get(var_name, match.group(0))

        return re.sub(r"\{\{(\w+)\}\}", replacer, text)

    def set_variable(self, name: str, value: str):
        self._variables[name] = value

    def get_variable(self, name: str) -> str | None:
        return self._variables.get(name)


class SessionCheckEngine:
    def __init__(self, event_bus: EventBus, macro_engine: MacroEngine):
        self.event_bus = event_bus
        self.macro_engine = macro_engine
        self._check_interval = 60
        self._task: asyncio.Task | None = None
        self._running = False
        self._check_rules: list[dict] = []

    async def start(self):
        self.event_bus.subscribe("response.received", self._on_response)
        await self._refresh_rules()
        self._running = True
        self._task = asyncio.create_task(self._periodic_check())

    async def stop(self):
        self._running = False
        self.event_bus.unsubscribe("response.received", self._on_response)
        self._check_rules.clear()
        if self._task:
            self._task.cancel()
            self._task = None

    async def _on_response(self, event: dict):
        if not self._check_rules:
            return
        for rule in self._check_rules:
            await self._run_check(rule)

    async def _periodic_check(self):
        while self._running:
            await asyncio.sleep(self._check_interval)
            for rule in self._check_rules:
                await self._run_check(rule)

    async def _run_check(self, rule: dict):
        config = rule.get("config", {})
        check_url = config.get("check_url", "")
        if not check_url:
            return

        import httpx
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.get(check_url)

            valid_status = config.get("valid_status", 200)
            if resp.status_code != valid_status:
                logger.warning("Session check failed for rule %s: status %d", rule.get("id"), resp.status_code)
                await self._reestablish_session(rule)

        except Exception as e:
            logger.error("Session check error for rule %s: %s", rule.get("id"), e)
            await self._reestablish_session(rule)

    async def _reestablish_session(self, rule: dict):
        config = rule.get("config", {})
        macro_config = config.get("reestablish_macro", [])
        if not macro_config:
            logger.warning("No reestablish macro configured for session check rule")
            return

        logger.info("Re-establishing session via macro for rule %s", rule.get("id"))
        session_id = uuid.UUID(config.get("session_id", "00000000-0000-0000-0000-000000000001"))
        results = await self.macro_engine.execute_macro(session_id, macro_config)
        await self.event_bus.publish({
            "type": "session.check.reestablished",
            "rule_id": rule.get("id"),
            "macro_results": results,
        })

    async def _refresh_rules(self):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SessionHandlingRule).where(
                    SessionHandlingRule.enabled == True,
                    SessionHandlingRule.rule_type == "session_check",
                )
            )
            self._check_rules = [
                {
                    "id": str(r.id),
                    "config": r.config,
                }
                for r in result.scalars().all()
            ]


class SessionHandlingEngine:
    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        self.cookie_jar = CookieJarEngine(event_bus)
        self.macro_engine = MacroEngine(event_bus)
        self.session_check = SessionCheckEngine(event_bus, self.macro_engine)
        self._recording: dict[str, dict] = {}
        self._recording_handler = self._on_request_captured

    async def start(self):
        await self.cookie_jar.start()
        await self.session_check.start()
        self.event_bus.subscribe("request.captured", self._recording_handler)
        logger.info("Session handling engine started")

    async def stop(self):
        await self.cookie_jar.stop()
        await self.session_check.stop()
        self.event_bus.unsubscribe("request.captured", self._recording_handler)
        self._recording.clear()
        logger.info("Session handling engine stopped")

    async def _on_request_captured(self, event: dict):
        if not self._recording:
            return
        session_id = event.get("session_id", "")
        rec = self._recording.get(session_id)
        if not rec or not rec.get("active"):
            return
        self._record_request(session_id, event)

    def _record_request(self, session_id: str, event: dict):
        rec = self._recording.get(session_id)
        if rec is None:
            return
        rec.setdefault("requests", []).append({
            "id": event.get("id", ""),
            "method": event.get("method", ""),
            "url": event.get("url", ""),
            "host": event.get("host", ""),
            "path": event.get("path", ""),
            "request_headers": event.get("headers", {}),
            "request_body": event.get("body", ""),
            "response_status": event.get("status", 0),
            "response_headers": event.get("response_headers", {}),
            "response_body": event.get("response_body", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
