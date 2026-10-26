import os
import re
import hashlib
import base64
import asyncio
from contextlib import asynccontextmanager
import uuid
import binascii
import urllib.parse
import time
import logging
from pathlib import Path
from itertools import product
import httpx

logger = logging.getLogger(__name__)
from core.events.bus import EventBus
from core.storage.models import FuzzJob, FuzzResult
from core.storage.database import AsyncSessionLocal


MARKER = "§"
MAX_CARTESIAN_PRODUCT = 500_000
# A fuzz job used to keep every request/response pair in a single JSON column: a
# 100k-payload run against a chatty endpoint could write hundreds of MB and
# freeze the UI. Keep the first N results and truncate each stored direction.
MAX_STORED_RESULTS = 5_000
MAX_RESULT_FIELD = 64 * 1024
# Concurrency used to be unbounded (one coroutine and one TLS client per
# payload). 20 in-flight requests keeps a site usable and the process small.
FUZZ_WORKERS = 20
# Results are written to ``fuzz_results`` in batches of this size: one commit
# per payload would make SQLite the bottleneck, one commit per job would keep
# every result in memory again.
RESULTS_BATCH = 100


def parse_raw_scheme(host: str, path: str) -> str:
    """Return the absolute URL a raw request line should target."""
    if path.startswith(("http://", "https://")):
        return path
    port = host.rsplit(":", 1)[1] if ":" in host else ""
    scheme = "https" if port in ("", "443", "8443") else "http"
    return f"{scheme}://{host}{path}"


def truncate_result(result: dict, limit: int = MAX_RESULT_FIELD) -> dict:
    """Bound the size of the request/response text stored per fuzz result."""
    for key in ("request", "response"):
        value = result.get(key)
        if isinstance(value, str) and len(value) > limit:
            result[key] = value[:limit]
            result["truncated"] = True
    return result


def build_result_row(job_id, seq: int, result: dict) -> FuzzResult:
    """Turn one in-flight result dict into a ``fuzz_results`` row."""
    result = truncate_result(result)
    return FuzzResult(
        job_id=job_id,
        seq=seq,
        payload=result.get("payload") or {},
        status=result.get("status"),
        size=result.get("size") or 0,
        time_ms=result.get("time_ms") or 0,
        error=result.get("error"),
        waf_detected=result.get("waf_detected"),
        grep_results=result.get("grep_results") or {},
        extracted=result.get("extracted") or {},
        request=result.get("request"),
        response=result.get("response"),
        truncated=bool(result.get("truncated")),
    )


class TokenBucket:
    def __init__(self, rate: float, burst: int | None = None):
        self.rate = rate
        self.burst = burst or max(1, int(rate))
        self.tokens = float(self.burst)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        # rate <= 0 means unlimited, matching the RoE convention. Before this
        # guard, a 0 rate made the bucket divide by zero on the second acquire
        # and every worker died, leaving the job "running" forever with 0/N.
        if self.rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(float(self.burst), self.tokens + elapsed * self.rate)
            self.last_refill = now
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            sleep = (1.0 - self.tokens) / self.rate
            self.tokens = 0.0
            self.last_refill = now + sleep
        await asyncio.sleep(sleep)
MAX_WORDLIST_SIZE = 100_000


class PayloadProcessor:
    @staticmethod
    def add_prefix(payload: str, prefix: str = "") -> str:
        return prefix + payload

    @staticmethod
    def add_suffix(payload: str, suffix: str = "") -> str:
        return payload + suffix

    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def hex_encode(payload: str) -> str:
        return payload.encode().hex()

    @staticmethod
    def hex_decode(payload: str) -> str:
        try:
            return bytes.fromhex(payload).decode(errors="replace")
        except (ValueError, binascii.Error):
            return payload

    @staticmethod
    def unicode_encode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def reverse(payload: str) -> str:
        return payload[::-1]

    @staticmethod
    def md5_hash(payload: str) -> str:
        return hashlib.md5(payload.encode()).hexdigest()

    @staticmethod
    def sha1_hash(payload: str) -> str:
        return hashlib.sha1(payload.encode()).hexdigest()

    @staticmethod
    def sha256_hash(payload: str) -> str:
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def to_upper(payload: str) -> str:
        return payload.upper()

    @staticmethod
    def to_lower(payload: str) -> str:
        return payload.lower()


WAF_SIGNATURES: list[dict] = [
    {"name": "cloudflare", "body": re.compile(r"cloudflare|cf-ray|__cfduid", re.I)},
    {"name": "cloudflare", "status": 503, "body": re.compile(r"Just a moment|Checking your browser", re.I)},
    {"name": "aws_waf", "headers": ["x-amzn-requestid", "x-amzn-trace-id"]},
    {"name": "aws_waf", "status": 403, "body": re.compile(r"Request blocked|WAF|AWS.WAF", re.I)},
    {"name": "akamai", "headers": ["x-akamai-transformed"]},
    {"name": "akamai", "status": 403, "body": re.compile(r"Reference #|Akamai", re.I)},
    {"name": "modsecurity", "headers": ["x-modsecurity"]},
    {"name": "modsecurity", "body": re.compile(r"ModSecurity|Not Acceptable|406 Not Acceptable", re.I)},
    {"name": "sucuri", "headers": ["x-sucuri-id", "x-sucuri-cache"]},
    {"name": "sucuri", "body": re.compile(r"Sucuri|cloudproxy", re.I)},
    {"name": "f5_bigip", "headers": ["x-sb-error"]},
    {"name": "f5_bigip", "body": re.compile(r"The requested URL was rejected|F5 Networks", re.I)},
    {"name": "imperva", "headers": ["x-iinfo"]},
    {"name": "imperva", "body": re.compile(r"Incapsula|imperva", re.I)},
    {"name": "wordfence", "body": re.compile(r"Wordfence|blocked by Wordfence", re.I)},
    {"name": "comodo", "body": re.compile(r"Comodo|cwatch", re.I)},
    {"name": "barracuda", "body": re.compile(r"Barracuda|Blocked by Barracuda", re.I)},
    {"name": "generic_waf", "status": 406, "body": re.compile(r"blocked|rejected|forbidden|denied|attack detected", re.I)},
    {"name": "generic_waf", "status": 429, "body": re.compile(r"rate limit|too many requests|slow down", re.I)},
    {"name": "generic_waf", "status": 403, "body": re.compile(r"blocked|rejected|forbidden|denied|attack detected", re.I)},
]

WAF_BLOCK_STATUSES: set[int] = {403, 429, 503, 406}


class FuzzerService:
    def __init__(self, event_bus: EventBus, wordlists_dir: str | Path | None = None):
        self.event_bus = event_bus
        self._cancel_flags: set[uuid.UUID] = set()
        self._waf_detected: dict[str, bool] = {}
        self._waf_backoff_until: dict[str, float] = {}
        self._consecutive_blocks: dict[str, int] = {}
        if wordlists_dir:
            self.wordlists_dir = Path(wordlists_dir)
        else:
            self.wordlists_dir = Path(__file__).parent / "wordlists"

    def detect_waf(self, status: int | None, headers: dict | None, body: str | None, target: str) -> str | None:
        if not headers:
            headers = {}
        if not body:
            body = ""
        for sig in WAF_SIGNATURES:
            sig_name = sig["name"]
            if "status" in sig and status != sig["status"]:
                continue
            if "body" in sig and not sig["body"].search(body):
                continue
            if "headers" in sig:
                if not any(h.lower() in {k.lower() for k in headers} for h in sig["headers"]):
                    continue
            return sig_name
        if status in WAF_BLOCK_STATUSES:
            return "unknown_waf"
        return None

    def apply_waf_backoff(self, target: str, waf_name: str | None) -> float:
        now = time.time()
        if waf_name is None:
            self._consecutive_blocks[target] = max(0, self._consecutive_blocks.get(target, 0) - 2)
            if target in self._waf_backoff_until:
                del self._waf_backoff_until[target]
            return 0.0

        self._waf_detected[target] = True
        self._consecutive_blocks[target] = self._consecutive_blocks.get(target, 0) + 1
        blocks = self._consecutive_blocks[target]

        delay = min(0.5 * (2 ** (blocks - 1)), 30.0)
        self._waf_backoff_until[target] = now + delay
        return delay

    def extract_positions(self, template: str) -> list[tuple[str, str, str]]:
        pattern = re.compile(r"§([^§]+)§")
        positions = []
        last_end = 0
        for m in pattern.finditer(template):
            name = m.group(1)
            before = template[last_end:m.start()]
            after = template[m.end():]
            positions.append((name, before, after))
            last_end = m.end()
        return positions

    def expand_wordlist(self, path: str) -> list[str]:
        if ".." in path:
            logger.warning("Blocked path traversal in wordlist: %s", path)
            return []

        p = Path(path)
        if p.is_absolute() or os.path.isabs(path):
            # Absolute paths are only honored for the wordlist directories Nyx
            # itself exposes via list_wordlists() — reading arbitrary files
            # from anywhere on disk is not acceptable.
            allowed_roots = [
                self.wordlists_dir.resolve(),
                (Path(__file__).parent / "wordlists").resolve(),
            ]
            try:
                resolved = p.resolve()
            except OSError:
                return []
            if not any(resolved.is_relative_to(root) for root in allowed_roots):
                logger.warning("Blocked wordlist outside allowed directories: %s", path)
                return []
            if not resolved.exists() or not resolved.is_file():
                logger.warning("Wordlist not found: %s", path)
                return []
            if resolved.suffix not in (".txt",):
                logger.warning("Only .txt wordlists allowed: %s", path)
                return []
            lines = [line.strip() for line in resolved.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            return lines[:MAX_WORDLIST_SIZE]

        wl_path = self.wordlists_dir / path
        if wl_path.exists():
            lines = [line.strip() for line in wl_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
            return lines[:MAX_WORDLIST_SIZE]
        try:
            import importlib.resources as res
            text = res.read_text("modules.fuzzer.wordlists", path)
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            return lines[:MAX_WORDLIST_SIZE]
        except (FileNotFoundError, ModuleNotFoundError):
            return []

    def list_wordlists(self) -> list[str]:
        """Return absolute paths for all built-in wordlists so the UI can pass them directly."""
        files: list[str] = []

        # Primary wordlists directory (configured by caller, usually backend/wordlists/)
        if self.wordlists_dir.exists():
            for f in sorted(self.wordlists_dir.iterdir()):
                if f.is_file() and f.suffix == ".txt":
                    files.append(str(f.resolve()))

        # Secondary: modules/fuzzer/wordlists/ for security payloads (sqli, xss, etc.)
        secondary = Path(__file__).parent / "wordlists"
        if secondary.exists() and secondary.resolve() != self.wordlists_dir.resolve():
            for f in sorted(secondary.iterdir()):
                if f.is_file() and f.suffix == ".txt":
                    abs_path = str(f.resolve())
                    if abs_path not in files:
                        files.append(abs_path)

        return files

    def generate_payloads(self, positions: list[dict], wordlists: dict[str, list[str]], attack_type: str) -> list[dict[str, str]]:
        pos_names = [p["name"] for p in positions]
        if not positions:
            return []

        if attack_type == "sniper":
            results = []
            for pos in positions:
                pname = pos["name"]
                wl = wordlists.get(pname, [])
                processors_list = pos.get("processors", [])
                for payload in wl:
                    processed = self.apply_processing(payload, processors_list)
                    mapping = {n: "" for n in pos_names}
                    mapping[pname] = processed
                    results.append(mapping)
            return results

        elif attack_type == "batteringram":
            first_pos = positions[0]
            wl = wordlists.get(first_pos["name"], [])
            results = []
            for payload in wl:
                mapping = {}
                for pos in positions:
                    pname = pos["name"]
                    processors_list = pos.get("processors", [])
                    mapping[pname] = self.apply_processing(payload, processors_list)
                results.append(mapping)
            return results

        elif attack_type == "pitchfork":
            max_len = max((len(wordlists.get(p["name"], [])) for p in positions), default=0)
            results = []
            for i in range(max_len):
                mapping = {}
                for pos in positions:
                    pname = pos["name"]
                    wl = wordlists.get(pname, [])
                    processors_list = pos.get("processors", [])
                    payload = wl[i] if i < len(wl) else ""
                    mapping[pname] = self.apply_processing(payload, processors_list)
                results.append(mapping)
            return results

        elif attack_type == "clusterbomb":
            all_wordlists = [wordlists.get(p["name"], []) for p in positions]
            total = 1
            for wl in all_wordlists:
                total *= len(wl)
                if total > MAX_CARTESIAN_PRODUCT:
                    logger.warning("Cartesian product %d exceeds limit %d, truncating", total, MAX_CARTESIAN_PRODUCT)
                    break
            results = []
            count = 0
            for combo in product(*all_wordlists):
                if count >= MAX_CARTESIAN_PRODUCT:
                    break
                mapping = {}
                for i, pos in enumerate(positions):
                    pname = pos["name"]
                    processors_list = pos.get("processors", [])
                    mapping[pname] = self.apply_processing(combo[i], processors_list)
                results.append(mapping)
                count += 1
            return results

        return []

    def apply_processing(self, payload: str, processors: list[str]) -> str:
        result = payload
        for proc in processors:
            if proc == "url_encode":
                result = PayloadProcessor.url_encode(result)
            elif proc == "double_url_encode":
                result = PayloadProcessor.double_url_encode(result)
            elif proc == "base64_encode":
                result = PayloadProcessor.base64_encode(result)
            elif proc == "hex_encode":
                result = PayloadProcessor.hex_encode(result)
            elif proc == "hex_decode":
                result = PayloadProcessor.hex_decode(result)
            elif proc == "unicode_encode":
                result = PayloadProcessor.unicode_encode(result)
            elif proc == "reverse":
                result = PayloadProcessor.reverse(result)
            elif proc == "md5_hash":
                result = PayloadProcessor.md5_hash(result)
            elif proc == "sha1_hash":
                result = PayloadProcessor.sha1_hash(result)
            elif proc == "sha256_hash":
                result = PayloadProcessor.sha256_hash(result)
            elif proc == "to_upper":
                result = PayloadProcessor.to_upper(result)
            elif proc == "to_lower":
                result = PayloadProcessor.to_lower(result)
            elif proc.startswith("add_prefix:"):
                result = PayloadProcessor.add_prefix(result, proc[len("add_prefix:"):])
            elif proc.startswith("add_suffix:"):
                result = PayloadProcessor.add_suffix(result, proc[len("add_suffix:"):])
        return result

    def _substitute(self, template: str, payloads: dict[str, str]) -> str:
        result = template
        for name, value in payloads.items():
            result = result.replace(f"§{name}§", value)
        return result

    VALID_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"}

    def _parse_raw_http(self, raw: str) -> dict:
        lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
        parts = lines[0].split(" ", 2)
        if len(parts) < 3 or parts[0].upper() not in self.VALID_HTTP_METHODS:
            raise ValueError("Invalid HTTP request line")
        method = parts[0]
        path = parts[1]
        headers = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            key, _, value = lines[i].partition(":")
            headers[key.strip()] = value.strip()
            i += 1
        body = "\n".join(lines[i + 1:]) if i + 1 < len(lines) else None
        host = headers.get("Host", "")
        # A raw HTTP template has no scheme. Assuming https made every fuzz
        # request to a plain-HTTP target fail with WRONG_VERSION_NUMBER.
        url = parse_raw_scheme(host, path)
        return {"method": method, "url": url, "headers": headers, "content": body}

    async def run_job(
        self,
        job_id: uuid.UUID,
        template: str,
        positions: list[dict],
        wordlists: dict[str, list[str]],
        attack_type: str,
        processors: list[str],
        grep_matches: list[dict],
        extractors: list[dict],
        rate_limit_rps: int,
    ):
        rate_limiter = TokenBucket(rate=float(rate_limit_rps))
        payload_mappings = self.generate_payloads(positions, wordlists, attack_type)
        total = len(payload_mappings)
        completed = 0

        job_session_id = None

        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            if job:
                job_session_id = job.session_id
                job.status = "running"
                job.total_requests = total
                await db.commit()

        # Scope/RoE gate before a single payload leaves the machine. The
        # template is a raw HTTP request; its URL is what the fuzzer will hit.
        target_url = None
        try:
            target_url = self._parse_raw_http(template).get("url")
        except ValueError:
            target_url = None
        if target_url:
            from core.authorization import authorize
            allowed, kind, detail = await authorize(job_session_id, target_url)
            if not allowed:
                async with AsyncSessionLocal() as db:
                    blocked = await db.get(FuzzJob, job_id)
                    if blocked:
                        blocked.status = "cancelled"
                        # The refusal is a result row too, so the UI shows why
                        # the job produced nothing instead of an empty table.
                        db.add(FuzzResult(
                            job_id=job_id,
                            seq=0,
                            payload={"url": target_url},
                            status=None,
                            error=f"Target not authorized ({kind}: {detail})",
                        ))
                        await db.commit()
                logger.warning(
                    "Fuzz job %s blocked: %s (%s)", job_id, target_url, kind
                )
                await self.event_bus.publish({
                    "type": "fuzz.blocked",
                    "job_id": str(job_id),
                    "url": target_url,
                    "reason": kind,
                    "detail": detail,
                })
                self._cancel_flags.discard(job_id)
                return

        # One client for the whole job: TLS handshakes are reused instead of
        # paying a new handshake for every payload.
        shared_http_client = httpx.AsyncClient(
            verify=False, timeout=10,
            limits=httpx.Limits(max_connections=FUZZ_WORKERS,
                                max_keepalive_connections=FUZZ_WORKERS // 2),
        )

        @asynccontextmanager
        async def shared_client():
            yield shared_http_client

        async def send_one(payload_map: dict[str, str]) -> dict | None:
            nonlocal completed
            if job_id in self._cancel_flags:
                return None

            await rate_limiter.acquire()
            request_str = self._substitute(template, payload_map)
            try:
                parsed = self._parse_raw_http(request_str)
            except ValueError:
                completed += 1
                return {
                    "payload": payload_map,
                    "error": "Invalid HTTP request line",
                    "status": None,
                    "size": 0,
                    "time_ms": 0,
                    "grep_results": {},
                    "extracted": {},
                    "request": request_str,
                    "response": None,
                }

            # Payload substitution can change the path or query that leaves
            # the machine, so the job-level check is not enough: authorize the
            # concrete URL of every payload.
            from core.authorization import authorize
            allowed, kind, detail = await authorize(
                job_session_id, parsed.get("url", "")
            )
            if not allowed:
                completed += 1
                logger.warning(
                    "Fuzz payload blocked for job %s (%s: %s)",
                    job_id, kind, detail,
                )
                return {
                    "payload": payload_map,
                    "error": f"Target not authorized ({kind}: {detail})",
                    "status": None,
                    "size": 0,
                    "time_ms": 0,
                    "grep_results": {},
                    "extracted": {},
                    "request": request_str,
                    "response": None,
                }

            async with shared_client() as client:
                try:
                    # Signed RoE max_rps applies to fuzz payloads too, not
                    # only to the job-level authorization check.
                    from core.roe import pace
                    await pace(parsed.get("url", ""))
                    resp = await client.request(**parsed)
                    body_text = resp.text
                    resp_headers_str = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                    response_str = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n{resp_headers_str}\r\n\r\n{body_text}"

                    target_host = parsed.get("url", "")
                    waf_name = self.detect_waf(resp.status_code, dict(resp.headers), body_text, target_host)
                    backoff_seconds = self.apply_waf_backoff(target_host, waf_name)
                    if backoff_seconds > 0 and not (job_id in self._cancel_flags):
                        await asyncio.sleep(backoff_seconds)

                    result = {
                        "payload": payload_map,
                        "status": resp.status_code,
                        "size": len(resp.content),
                        "time_ms": int(resp.elapsed.total_seconds() * 1000),
                        "error": None,
                        "waf_detected": waf_name,
                        "grep_results": {},
                        "extracted": {},
                        "request": request_str,
                        "response": response_str,
                    }

                    for gm in grep_matches:
                        name = gm.get("name", "")
                        pattern = gm.get("pattern", "")
                        is_regex = gm.get("is_regex", False)
                        if is_regex:
                            result["grep_results"][name] = bool(re.search(pattern, body_text))
                        else:
                            result["grep_results"][name] = pattern in body_text

                    for ext in extractors:
                        name = ext.get("name", "")
                        pattern = ext.get("pattern", "")
                        is_regex = ext.get("is_regex", False)
                        group = ext.get("group", 0)
                        if is_regex:
                            m = re.search(pattern, body_text)
                            if m:
                                # lastindex is None when the pattern has no
                                # capturing groups, and comparing int <= None
                                # raised TypeError mid-job (BUG-12).
                                lastindex = m.lastindex or 0
                                result["extracted"][name] = (
                                    m.group(group) if 0 < group <= lastindex
                                    else m.group(0)
                                )
                            else:
                                result["extracted"][name] = None
                        else:
                            idx = body_text.find(pattern)
                            if idx != -1:
                                result["extracted"][name] = pattern
                            else:
                                result["extracted"][name] = None

                except Exception as e:
                    result = {
                        "payload": payload_map,
                        "error": str(e),
                        "status": None,
                        "size": 0,
                        "time_ms": 0,
                        "grep_results": {},
                        "extracted": {},
                        "request": request_str,
                        "response": None,
                    }

            completed += 1
            if completed % 50 == 0:
                await self.event_bus.publish({
                    "type": "fuzz.progress",
                    "job_id": job_id,
                    "completed": completed,
                    "total": total,
                    "last_payload": str(payload_map),
                })

            return result

        # Bounded worker pool over a queue: at most FUZZ_WORKERS payloads are
        # in flight, and cancellation is honoured between items.
        work_queue: asyncio.Queue = asyncio.Queue()
        for payload_map in payload_mappings:
            work_queue.put_nowait(payload_map)

        # Results are streamed to fuzz_results in batches instead of being
        # accumulated and written as one JSON blob at the end (BUG-04 fase B).
        batch: list[FuzzResult] = []
        stored = 0

        async def flush_results():
            nonlocal batch
            if not batch:
                return
            rows, batch = batch, []
            async with AsyncSessionLocal() as db:
                db.add_all(rows)
                # Also refresh the counter the UI polls, so progress moves
                # during the run and not only when the job finishes.
                job = await db.get(FuzzJob, job_id)
                if job is not None:
                    job.completed_requests = completed
                await db.commit()

        async def fuzz_worker():
            nonlocal stored
            while True:
                try:
                    payload_map = work_queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                if job_id in self._cancel_flags:
                    continue
                result = await send_one(payload_map)
                if result is not None and stored < MAX_STORED_RESULTS:
                    batch.append(build_result_row(job_id, stored, result))
                    stored += 1
                    if len(batch) >= RESULTS_BATCH:
                        await flush_results()

        worker_count = min(FUZZ_WORKERS, max(1, total))
        try:
            await asyncio.gather(*(fuzz_worker() for _ in range(worker_count)))
        except Exception:
            # A crashing worker must not leave the job stuck in "running".
            logger.exception("Fuzz job %s worker failed", job_id)
        finally:
            await shared_http_client.aclose()

        if completed > stored:
            logger.warning(
                "Fuzz job %s completed %d payloads; stored %d (cap %d)",
                job_id, completed, stored, MAX_STORED_RESULTS,
            )
        await flush_results()

        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            if job:
                if job_id in self._cancel_flags:
                    job.status = "cancelled"
                else:
                    job.status = "done"
                job.completed_requests = completed
                await db.commit()

        self._cancel_flags.discard(job_id)

    def cancel_job(self, job_id: uuid.UUID):
        self._cancel_flags.add(job_id)
