import os
import re
import hashlib
import base64
import asyncio
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
from core.storage.models import FuzzJob
from core.storage.database import AsyncSessionLocal


MARKER = "§"
MAX_CARTESIAN_PRODUCT = 500_000


class TokenBucket:
    def __init__(self, rate: float, burst: int | None = None):
        self.rate = rate
        self.burst = burst or max(1, int(rate))
        self.tokens = float(self.burst)
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
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
        # Windows-style drive letters must be treated as absolute on every OS:
        # on POSIX, Path("C:/Windows/win.ini").is_absolute() is False and it
        # would fall through to the relative branch and raise. PurePath cannot
        # parse foreign-platform syntax, so match the drive prefix explicitly.
        _looks_abs = p.is_absolute() or os.path.isabs(path) or re.match(r"^[A-Za-z]:[/\\]", path)
        if _looks_abs:
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
        scheme = "https"
        url = f"{scheme}://{host}{path}"
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

        results_list = []

        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            if job:
                job.status = "running"
                job.total_requests = total
                await db.commit()

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

            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                try:
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
                                result["extracted"][name] = m.group(group) if group <= m.lastindex else m.group(0)
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

        tasks = [send_one(pm) for pm in payload_mappings]
        done = await asyncio.gather(*tasks)

        for r in done:
            if r is not None:
                results_list.append(r)

        async with AsyncSessionLocal() as db:
            job = await db.get(FuzzJob, job_id)
            if job:
                if job_id in self._cancel_flags:
                    job.status = "cancelled"
                else:
                    job.status = "done"
                job.completed_requests = len(results_list)
                job.results = results_list
                await db.commit()

        self._cancel_flags.discard(job_id)

    def cancel_job(self, job_id: uuid.UUID):
        self._cancel_flags.add(job_id)
