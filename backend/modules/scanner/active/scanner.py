import asyncio
import logging
import time
import uuid
from urllib.parse import urlparse
from core.config import settings
from core.events.bus import EventBus
from core.storage.finding_events import persist_results
from modules.scanner.fingerprint import fingerprint_server, select_checks_for_target
from modules.scanner.cvss_mapper import get_cvss_for_cwe

logger = logging.getLogger(__name__)


def normalize_base_request(base_request: dict) -> dict:
    """Translate the UI/CLI ``body`` key into what httpx understands.

    Checks call ``client.request(**request)``; httpx accepts ``content``, not
    ``body``. Every request-based check was therefore raising TypeError inside
    its ``except Exception: continue``, silently producing zero findings for
    anything that needed a probe. Evidence keeps the original event shape.
    """
    request = dict(base_request)
    body = request.pop("body", None)
    if body is not None and "content" not in request and "data" not in request:
        request["content"] = body
    return request


def remember_finding(result, seen: set) -> bool:
    """Return True the first time a weakness is reported for a parameter.

    Several checks cover the same weakness (error-based and variant XSS, LDAP
    payload families): keying on the title kept every one of them and a single
    reflected parameter produced three findings. The stable identity of a
    finding is (CWE, parameter); the title is only a fallback for checks that
    do not set a CWE. Different parameters stay distinct (BUG-02).
    """
    cwe = str(getattr(result, "cwe", None) or "")
    param = str(getattr(result, "param", None) or "")
    if cwe:
        key = ("cwe", cwe, param)
    else:
        key = ("title", str(getattr(result, "title", None) or ""), param)
    if key in seen:
        return False
    seen.add(key)
    return True


class ActiveScanner:
    def __init__(self, event_bus: EventBus | None = None):
        self.event_bus = event_bus
        self._checks: list | None = None

    @property
    def checks(self):
        if self._checks is None:
            self._checks = self._build_checks()
        return self._checks

    def _build_checks(self) -> list:
        # Registration lives in the checks package: importing a new check
        # module is the only step needed to make it run.
        from modules.scanner.active.registry import active_checks

        return active_checks()

    async def fingerprint(self, target_url: str) -> dict:
        return await fingerprint_server(target_url)

    async def discover_params(self, target_url: str, concurrency: int = 5, session_id: str | None = None) -> list[dict]:
        try:
            from modules.automations.param_chain import ParamDiscoveryService
            service = ParamDiscoveryService(self.event_bus or EventBus())
            result = await service.discover(target_url, concurrency, session_id=session_id)
            return result.get("discovered_params", [])
        except Exception as e:
            logger.error("Param discovery failed for %s: %s", target_url, e)
            return []

    async def run_checks(
        self,
        base_request: dict,
        target_params: list[str],
        event: dict | None = None,
        fingerprint_info: dict | None = None,
        checks_filter: list[str] | None = None,
        depth: str | None = None,
        deadline_seconds: float | None = None,
    ) -> list[dict]:
        """Run the selected checks against one request.

        Checks execute concurrently behind a semaphore (they are independent
        and network-bound), but results are processed in registration order so
        deduplication and persisted findings stay deterministic. A wall-clock
        deadline returns the checks that finished instead of cancelling the
        whole scan.
        """
        from modules.scanner.scan_depth import get_depth
        from modules.scanner.base_check import (
            reset_payload_budget,
            set_payload_budget,
        )

        depth_profile = get_depth(depth)

        all_results: list[dict] = []
        checks_to_run = list(self.checks)

        if checks_filter:
            checks_to_run = [
                c for c in checks_to_run
                if c.name in checks_filter or any(f in c.name for f in checks_filter)
            ]

        # Depth-based filtering: fast profile skips heavy checks (blind/time/OAST)
        checks_to_run = [
            c for c in checks_to_run if not depth_profile.skip_check(c.name)
        ]

        if fingerprint_info:
            selection = select_checks_for_target(fingerprint_info)
            prioritize_names = selection.get("prioritize", [])
            skip_names = selection.get("skip", [])
            if skip_names:
                # A detected WAF already told us these probes will be blocked
                # or answered by the WAF itself. Requesting them anyway burns
                # the rate budget and produces WAF findings, not target ones.
                checks_to_run = [
                    c for c in checks_to_run
                    if not any(name in c.name for name in skip_names)
                ]
            if prioritize_names:
                prioritized = [c for c in checks_to_run if c.name in prioritize_names]
                rest = [c for c in checks_to_run if c.name not in prioritize_names]
                checks_to_run = prioritized + rest

        # Depth-based budget: the profile caps BOTH how many parameters a check
        # sees and how many payloads it sends per parameter.
        max_payloads = depth_profile.max_payloads_per_param
        params_for_scan = target_params
        if len(target_params) > max_payloads:
            params_for_scan = target_params[:max_payloads]

        # Scope is a hard barrier, not a UI filter: resolve the session that
        # produced this request and refuse to probe URLs it did not authorize.
        # No rules configured means "allow", matching check_scope().
        raw_session_id = event.get("session_id") if event else None
        session_id = None
        if raw_session_id:
            try:
                session_id = uuid.UUID(str(raw_session_id))
            except (TypeError, ValueError):
                session_id = None
        if settings.SCAN_ENFORCE_SCOPE:
            from core.authorization import authorize
            # Pass the raw value: authorize() fails closed on malformed ids
            # instead of degrading to an unscoped scan.
            allowed, kind, detail = await authorize(
                raw_session_id, base_request.get("url", "")
            )
            if not allowed:
                logger.info(
                    "Active scan refused: %s (%s: %s)",
                    base_request.get("url", ""), kind, detail,
                )
                if self.event_bus:
                    await self.event_bus.publish({
                        "type": "scan.skipped",
                        "url": base_request.get("url", ""),
                        "session_id": str(session_id) if session_id else None,
                        "reason": kind,
                        "rule": detail,
                    })
                return []

        request_for_checks = normalize_base_request(base_request)

        seen_findings: set = set()
        started = time.monotonic()
        deadline = started + deadline_seconds if deadline_seconds else None
        semaphore = asyncio.Semaphore(max(1, int(settings.SCAN_MAX_CONCURRENCY)))
        budget_reported = False
        target_url = base_request.get("url", "")

        async def run_one(check):
            nonlocal budget_reported
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                if self.event_bus and not budget_reported:
                    budget_reported = True
                    await self.event_bus.publish({
                        "type": "scan.budget_exhausted",
                        "url": target_url,
                        "session_id": str(session_id) if session_id else None,
                    })
                return check, None

            async with semaphore:
                # Re-check authorization for every check: a long scan can run
                # past its RoE window, and a profile can be deactivated while
                # the scan is in flight. The initial gate alone is not enough.
                if settings.SCAN_ENFORCE_SCOPE:
                    from core.authorization import authorize
                    allowed, kind, detail = await authorize(
                        raw_session_id, target_url
                    )
                    if not allowed:
                        logger.info(
                            "Active check %s refused (%s: %s)",
                            check.name, kind, detail,
                        )
                        if self.event_bus:
                            await self.event_bus.publish({
                                "type": "scan.skipped",
                                "url": target_url,
                                "check": check.name,
                                "session_id": str(session_id) if session_id else None,
                                "reason": kind,
                                "rule": detail,
                            })
                        return check, None

                # RoE pacing is enforced per probe, not once per engagement:
                # a signed max_rps is a ceiling on what actually leaves the box.
                try:
                    from core.roe import pace
                    await pace(target_url)
                except Exception:
                    logger.debug("RoE pacing lookup failed", exc_info=True)

                timeout = settings.SCAN_CHECK_TIMEOUT_SECONDS
                if remaining is not None:
                    timeout = min(timeout, max(0.01, remaining))
                try:
                    results = await asyncio.wait_for(
                        check.run(request_for_checks, params_for_scan),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Check %s timed out after %.0fs on %s",
                        check.name, timeout, target_url,
                    )
                    if self.event_bus:
                        await self.event_bus.publish({
                            "type": "scan.check_timeout",
                            "check": check.name,
                            "url": target_url,
                            "session_id": str(session_id) if session_id else None,
                        })
                    return check, []
                except Exception as e:
                    logger.error("Active check %s failed: %s", check.name, e)
                    return check, []
            return check, results

        token = set_payload_budget(max_payloads)
        try:
            completed = await asyncio.gather(*(run_one(c) for c in checks_to_run))
        finally:
            reset_payload_budget(token)

        for check, results in completed:
            if not results:
                continue

            # Apply CVSS and deduplicate in registration order.
            unique_results = []
            for r in results:
                if not r.triggered:
                    continue
                if not remember_finding(r, seen_findings):
                    continue
                cvss_info = get_cvss_for_cwe(r.cwe) if r.cwe else None
                if cvss_info:
                    r.cvss_score = cvss_info["score"]
                    r.cvss_vector = cvss_info["vector"]
                    if not hasattr(r, "severity") or r.severity == "info":
                        r.severity = cvss_info["severity"]
                unique_results.append(r)

            if unique_results and self.event_bus:
                await persist_results(
                    self.event_bus, unique_results, event or base_request,
                    check.name, source="active",
                )

            for r in unique_results:
                all_results.append({
                    "check": check.name,
                    "severity": r.severity,
                    "title": r.title,
                    "description": r.description,
                    "evidence": r.evidence,
                    "remediation": r.remediation,
                    "cwe": r.cwe,
                    "cvss_score": getattr(r, "cvss_score", None),
                    "cvss_vector": getattr(r, "cvss_vector", None),
                })
                logger.info(
                    "Active check %s: %s (CVSS: %s)",
                    check.name, r.title, getattr(r, "cvss_score", "N/A"),
                )
        return all_results
