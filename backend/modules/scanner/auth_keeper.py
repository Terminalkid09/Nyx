"""
Auto-Auth Keeper
================
Transparently re-authenticates sessions during long scans.

Workflow:
1. Listens to `request.captured` / `response.received` events on the EventBus.
2. Detects successful login requests (heuristic: POST to auth-like endpoints + response
   that contains a token/cookie).
3. When the Scanner or Fuzzer receives a 401/403 (via `scan.auth_failure` event), the
   keeper replays the last detected login request, extracts the new credentials and
   updates the global auth headers/cookies dictionary.
4. Emits `auth_keeper.refreshed` once the new credentials are ready so the caller can
   resume with the updated headers.
"""

import copy
import json
import logging
import re
import time
from typing import Any

import httpx

from core.events.bus import EventBus

logger = logging.getLogger(__name__)

# ── Heuristics ─────────────────────────────────────────────────────────────

_LOGIN_PATH_PATTERNS = re.compile(
    r"/(login|signin|sign-in|auth|authenticate|token|session|oauth|sso|oidc|account/login|api/auth)",
    re.IGNORECASE,
)

_TOKEN_RESPONSE_PATTERNS = [
    re.compile(r'"access_token"\s*:\s*"([^"]+)"'),
    re.compile(r'"token"\s*:\s*"([^"]+)"'),
    re.compile(r'"jwt"\s*:\s*"([^"]+)"'),
    re.compile(r'"id_token"\s*:\s*"([^"]+)"'),
    re.compile(r'"auth_token"\s*:\s*"([^"]+)"'),
    re.compile(r'"session_token"\s*:\s*"([^"]+)"'),
]

_COOKIE_PATTERN = re.compile(
    r"(session|sid|auth|token|jwt|jsessionid|phpsessid|access_token)=([^;\s]+)",
    re.IGNORECASE,
)


class LoginCandidate:
    """Represents a captured, successful login request."""

    def __init__(self, method: str, url: str, headers: dict, body: str | None):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
        self.captured_at = time.time()

    def to_httpx_request(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "headers": {k: v for k, v in self.headers.items()
                        if k.lower() not in ("host", "content-length")},
            "content": self.body.encode() if self.body else None,
        }


class AuthKeeper:
    """
    Subscribes to the EventBus and automatically re-authenticates
    when a scan reports an auth failure.
    """

    def __init__(self, event_bus: EventBus):
        self.event_bus = event_bus
        # Latest known-good login candidate per session_id
        self._candidates: dict[str, LoginCandidate] = {}
        # Latest extracted credentials per session_id
        self._live_creds: dict[str, dict] = {}
        # Simple lock flag to avoid concurrent refresh races
        self._refreshing: set[str] = set()

        event_bus.subscribe("request.captured", self._on_request)
        event_bus.subscribe("response.received", self._on_response)
        event_bus.subscribe("scan.auth_failure", self._on_auth_failure)

    # ── Internal helpers ────────────────────────────────────────────────────

    def _session_key(self, event: dict) -> str:
        return str(event.get("session_id") or "default")

    @staticmethod
    def _is_login_request(method: str, url: str) -> bool:
        return method.upper() == "POST" and bool(_LOGIN_PATH_PATTERNS.search(url))

    @staticmethod
    def _extract_credentials(response_body: str, response_headers: dict) -> dict | None:
        """Try to extract a bearer token or session cookie from a login response."""
        creds: dict[str, Any] = {}

        # Check JSON body for tokens
        for pattern in _TOKEN_RESPONSE_PATTERNS:
            m = pattern.search(response_body or "")
            if m:
                creds["bearer"] = m.group(1)
                break

        # Check Set-Cookie header
        set_cookie = response_headers.get("set-cookie") or response_headers.get("Set-Cookie") or ""
        if isinstance(set_cookie, list):
            set_cookie = "; ".join(set_cookie)
        for m in _COOKIE_PATTERN.finditer(set_cookie):
            creds.setdefault("cookies", {})[m.group(1)] = m.group(2)

        return creds if creds else None

    @staticmethod
    def _apply_credentials(headers: dict, creds: dict) -> dict:
        """Return a copy of *headers* with fresh credentials applied."""
        h = copy.deepcopy(headers)
        if "bearer" in creds:
            h["Authorization"] = f"Bearer {creds['bearer']}"
        if "cookies" in creds:
            existing = h.get("Cookie", "")
            patches = "; ".join(f"{k}={v}" for k, v in creds["cookies"].items())
            h["Cookie"] = f"{existing}; {patches}".strip("; ") if existing else patches
        return h

    # ── EventBus handlers ───────────────────────────────────────────────────

    async def _on_request(self, event: dict):
        """Intercept outgoing requests to detect login candidates."""
        method = (event.get("method") or "").upper()
        url = event.get("url") or ""
        if not self._is_login_request(method, url):
            return
        sid = self._session_key(event)
        self._candidates[sid] = LoginCandidate(
            method=method,
            url=url,
            headers=dict(event.get("request_headers") or {}),
            body=event.get("request_body"),
        )
        logger.debug("[AuthKeeper] Captured login candidate for session %s: %s", sid, url)

    async def _on_response(self, event: dict):
        """After a successful login response, extract and cache credentials."""
        sid = self._session_key(event)
        candidate = self._candidates.get(sid)
        if not candidate:
            return

        status = event.get("status") or 0
        if status not in (200, 201):
            return

        body = event.get("body") or ""
        headers = dict(event.get("headers") or {})
        creds = self._extract_credentials(body, headers)
        if creds:
            self._live_creds[sid] = creds
            logger.info("[AuthKeeper] Credentials cached for session %s (bearer=%s, cookies=%s)",
                        sid, bool(creds.get("bearer")), list(creds.get("cookies", {}).keys()))
            await self.event_bus.publish({
                "type": "auth_keeper.credentials_cached",
                "session_id": sid,
                "has_bearer": bool(creds.get("bearer")),
                "cookie_names": list(creds.get("cookies", {}).keys()),
            })

    async def _on_auth_failure(self, event: dict):
        """Called when a scan signals a 401/403. Attempt transparent re-auth."""
        sid = self._session_key(event)

        if sid in self._refreshing:
            logger.debug("[AuthKeeper] Refresh already in progress for session %s", sid)
            return

        candidate = self._candidates.get(sid)
        if not candidate:
            logger.warning("[AuthKeeper] No login candidate for session %s — cannot refresh", sid)
            await self.event_bus.publish({
                "type": "auth_keeper.refresh_failed",
                "session_id": sid,
                "reason": "no_login_candidate",
            })
            return

        self._refreshing.add(sid)
        logger.info("[AuthKeeper] Auth failure detected for session %s, replaying login to %s",
                    sid, candidate.url)

        try:
            req_kwargs = candidate.to_httpx_request()
            async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
                resp = await client.request(**req_kwargs)

            body_text = resp.text
            resp_headers = dict(resp.headers)
            creds = self._extract_credentials(body_text, resp_headers)

            if not creds:
                logger.warning("[AuthKeeper] Login replay did not yield credentials (status=%s)", resp.status_code)
                await self.event_bus.publish({
                    "type": "auth_keeper.refresh_failed",
                    "session_id": sid,
                    "reason": "no_credentials_extracted",
                    "login_status": resp.status_code,
                })
                return

            self._live_creds[sid] = creds
            logger.info("[AuthKeeper] Session %s refreshed successfully", sid)
            await self.event_bus.publish({
                "type": "auth_keeper.refreshed",
                "session_id": sid,
                "credentials": creds,
            })

        except Exception as e:
            logger.error("[AuthKeeper] Refresh failed for session %s: %s", sid, e)
            await self.event_bus.publish({
                "type": "auth_keeper.refresh_failed",
                "session_id": sid,
                "reason": str(e),
            })
        finally:
            self._refreshing.discard(sid)

    # ── Public API ──────────────────────────────────────────────────────────

    def patch_request_headers(self, session_id: str, headers: dict) -> dict:
        """
        Utility for the scanner/fuzzer: returns *headers* updated with the
        latest known credentials for *session_id*. Call this before re-issuing
        a request after receiving `auth_keeper.refreshed`.
        """
        creds = self._live_creds.get(str(session_id))
        if not creds:
            return headers
        return self._apply_credentials(headers, creds)

    def get_credentials(self, session_id: str) -> dict | None:
        return self._live_creds.get(str(session_id))

    def get_status(self) -> dict:
        return {
            "sessions_with_candidates": list(self._candidates.keys()),
            "sessions_with_creds": list(self._live_creds.keys()),
            "currently_refreshing": list(self._refreshing),
        }
