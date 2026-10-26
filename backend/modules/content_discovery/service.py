import asyncio
import difflib
import hashlib
import logging
import re
import time
import uuid
from pathlib import Path

import httpx

from core.authorization import authorize
from core.events.bus import EventBus
from core.roe import pace
from core.storage.finding_events import persist_results
from core.storage.traffic import DEFAULT_SESSION_ID
from modules.scanner.base_check import CheckResult

logger = logging.getLogger(__name__)

MAX_WORDLIST_SIZE = 100_000
# A soft 404 often echoes the requested path, so two random paths produce
# different bodies. Normalising digits and the random token is what makes the
# fingerprints comparable.
_NORMALISE_RE = re.compile(r"\d{2,}")


def _normalise_body(body: str, requested_path: str = "") -> str:
    """Lowercase, drop the requested path and collapse volatile numbers.

    Two random probes produce different bodies when the app echoes the path
    ("page /nyx-not-found-abc not found"). Removing that path is what makes
    the bodies comparable; without it only a length heuristic works.
    """
    text = body.lower()
    if requested_path:
        text = text.replace(requested_path.lower().strip("/"), "")
        text = text.replace(requested_path.lower(), "")
    text = _NORMALISE_RE.sub("#", text)
    return re.sub(r"\s+", " ", text).strip()


def _body_fingerprint(body: str, requested_path: str = "") -> str:
    normalised = _normalise_body(body, requested_path)[:8192]
    return hashlib.sha256(normalised.encode("utf-8", "replace")).hexdigest()


class ContentDiscoveryService:
    def __init__(
        self,
        event_bus: EventBus,
        wordlists_dir: str | Path | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.event_bus = event_bus
        self._cancel_flags: set[uuid.UUID] = set()
        if wordlists_dir:
            self.wordlists_dir = Path(wordlists_dir)
        else:
            self.wordlists_dir = Path(__file__).parent.parent.parent / "wordlists"
        self._transport = transport

    def list_wordlists(self) -> list[str]:
        return [item["path"] for item in self.wordlist_metadata()]

    def wordlist_metadata(self) -> list[dict]:
        """Describe the bundled/imported wordlists (path, name, size, lines)."""
        files = []
        if not self.wordlists_dir.exists():
            return files
        for f in sorted(self.wordlists_dir.iterdir()):
            if not f.is_file() or f.suffix != ".txt":
                continue
            try:
                lines = sum(
                    1
                    for line in f.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
                size = f.stat().st_size
            except OSError:
                continue
            files.append({
                "path": str(f.resolve()),
                "name": f.name,
                "size_bytes": size,
                "lines": lines,
            })
        return files

    # ── Wordlist management ──────────────────────────────────────────────
    NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.txt$")
    MAX_UPLOAD_BYTES = 8 * 1024 * 1024

    def _safe_wordlist_path(self, name: str) -> Path | None:
        if not self.NAME_RE.match(name or ""):
            return None
        return self.wordlists_dir / name

    def save_wordlist(self, name: str, content: str) -> dict:
        path = self._safe_wordlist_path(name)
        if path is None:
            return {"error": "Invalid wordlist name (expected file.txt)"}
        raw = (content or "").encode("utf-8")
        if len(raw) > self.MAX_UPLOAD_BYTES:
            return {"error": f"Wordlist exceeds {self.MAX_UPLOAD_BYTES} bytes"}
        lines = [
            line.strip() for line in (content or "").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not lines:
            return {"error": "Wordlist is empty"}
        if len(lines) > MAX_WORDLIST_SIZE:
            lines = lines[:MAX_WORDLIST_SIZE]
        # De-duplicate while preserving order; an uploaded list is often the
        # concatenation of several sources.
        seen: set[str] = set()
        unique = [line for line in lines if not (line in seen or seen.add(line))]
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(unique) + "\n", encoding="utf-8")
        return {"name": path.name, "path": str(path.resolve()), "lines": len(unique)}

    def preview_wordlist(self, name: str, limit: int = 50) -> dict:
        path = self._safe_wordlist_path(name)
        if path is None or not path.is_file():
            return {"error": "Wordlist not found"}
        lines, error = self._read_wordlist(str(path))
        if error:
            return {"error": error}
        limit = max(1, min(limit, 200))
        return {
            "name": path.name,
            "lines": len(lines),
            "preview": lines[:limit],
        }

    def delete_wordlist(self, name: str) -> dict:
        path = self._safe_wordlist_path(name)
        if path is None or not path.is_file():
            return {"error": "Wordlist not found"}
        path.unlink()
        return {"deleted": path.name}

    def _read_wordlist(self, wordlist_path: str) -> tuple[list[str] | None, str | None]:
        if ".." in wordlist_path:
            return None, "Path traversal blocked"
        p = Path(wordlist_path)
        wordlist_file = p if p.is_absolute() else (self.wordlists_dir / wordlist_path)
        if not wordlist_file.exists() or not wordlist_file.is_file():
            return None, f"Wordlist not found: {wordlist_path}"
        if wordlist_file.suffix != ".txt":
            return None, "Only .txt wordlists are supported"
        lines = [
            line.strip()
            for line in wordlist_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if len(lines) > MAX_WORDLIST_SIZE:
            logger.warning(
                "Wordlist %s truncated from %d to %d entries",
                wordlist_file, len(lines), MAX_WORDLIST_SIZE,
            )
            lines = lines[:MAX_WORDLIST_SIZE]
        return lines, None

    async def discover(
        self,
        target_url: str,
        wordlist_path: str,
        extensions: list[str] | None = None,
        methods: list[str] | None = None,
        throttle_ms: int = 0,
        session_id: str | None = None,
        concurrency: int = 20,
        recursive: bool = False,
        max_depth: int = 1,
    ) -> dict:
        job_id = uuid.uuid4()
        if extensions is None:
            extensions = [""]
        if methods is None:
            methods = ["GET"]

        allowed, kind, detail = await authorize(session_id, target_url)
        if not allowed:
            await self.event_bus.publish({
                "type": "content_discovery.blocked",
                "job_id": str(job_id),
                "target_url": target_url,
                "reason": kind,
                "rule": detail,
            })
            return {
                "job_id": str(job_id),
                "target_url": target_url,
                "discovered": [],
                "total": 0,
                "completed": 0,
                "status": "blocked",
                "error": f"Target not authorized ({kind}: {detail})",
            }

        lines, error = self._read_wordlist(wordlist_path)
        if error:
            return {"job_id": str(job_id), "error": error}

        total = len(lines) * len(extensions) * len(methods)
        discovered: list[dict] = []
        completed = 0
        completed_lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(max(1, min(concurrency, 100)))

        client_kwargs: dict = {
            "verify": False,
            "timeout": 10,
            "follow_redirects": False,
            "limits": httpx.Limits(
                max_connections=max(20, concurrency * 2),
                max_keepalive_connections=max(10, concurrency),
            ),
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            # ── Soft-404 calibration ─────────────────────────────────────
            # One random path is not enough: many apps reflect the path in the
            # error page, so two probes are compared and a signature is only
            # trusted when both agree.
            wildcard_samples: list[tuple[int, str, int]] = []
            for _ in range(2):
                random_path = f"nyx-not-found-{uuid.uuid4().hex}"
                url = target_url.rstrip("/") + "/" + random_path
                allowed, _kind, _detail = await authorize(session_id, url)
                if not allowed:
                    continue
                try:
                    await pace(url)
                    resp = await client.request(methods[0], url)
                except Exception as e:
                    logger.debug("Wildcard check failed: %s", e)
                    continue
                if resp.status_code != 404:
                    wildcard_samples.append((
                        resp.status_code,
                        _normalise_body(resp.text or "", random_path),
                        len(resp.content),
                    ))

            def is_soft_404(resp: httpx.Response, requested_path: str) -> bool:
                if not wildcard_samples:
                    return False
                body = _normalise_body(resp.text or "", requested_path)
                length = len(resp.content)
                for status, wildcard_body, wildcard_length in wildcard_samples:
                    if resp.status_code != status:
                        continue
                    if wildcard_body and difflib.SequenceMatcher(
                        None, body[:4096], wildcard_body[:4096]
                    ).ratio() >= 0.90:
                        return True
                    # Length alone is only meaningful on real pages: on a tiny
                    # generic error body a handful of bytes separates a hit
                    # from noise, so small bodies rely on similarity only.
                    if wildcard_length > 256:
                        tolerance = max(16, int(wildcard_length * 0.03))
                        if abs(length - wildcard_length) <= tolerance:
                            return True
                return False

            SENSITIVE_EXTS = {
                ".env", ".bak", ".sql", ".zip", ".tar.gz", ".git", ".config",
                "config.php", "web.config",
            }

            async def check_path(base_url: str, raw_path: str, method: str) -> dict | None:
                nonlocal completed
                if job_id in self._cancel_flags:
                    return None
                url = base_url.rstrip("/") + "/" + raw_path.lstrip("/")
                # A wordlist can generate an excluded path even when the base
                # URL is authorized. Re-check every candidate, not just the
                # starting URL.
                allowed, kind, detail = await authorize(session_id, url)
                if not allowed:
                    await self.event_bus.publish({
                        "type": "content_discovery.blocked",
                        "job_id": str(job_id),
                        "url": url,
                        "reason": kind,
                        "rule": detail,
                    })
                    return None
                try:
                    await pace(url)
                    start = time.monotonic()
                    resp = await client.request(method, url)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                except Exception as e:
                    logger.debug("Request failed for %s %s: %s", method, url, e)
                    return None

                if resp.status_code != 404 and not is_soft_404(resp, raw_path):
                    is_sensitive = any(
                        raw_path.endswith(ext) or raw_path.startswith(ext.strip("."))
                        for ext in SENSITIVE_EXTS
                    )
                    if is_sensitive:
                        # Persist through the same pipeline as scanner findings:
                        # a broadcast-only event never reached the findings
                        # table, the report or the attack-path graph.
                        finding = CheckResult(
                            triggered=True,
                            severity="high",
                            title=f"Sensitive File Exposed: {raw_path}",
                            description=(
                                f"Content discovery found a potentially sensitive "
                                f"file at `{url}`."
                            ),
                            evidence=(
                                f"Status Code: {resp.status_code}\n"
                                f"Size: {len(resp.content)} bytes"
                            ),
                            remediation=(
                                "Remove the file from the web root or restrict "
                                "access to it."
                            ),
                            cwe="CWE-200",
                        )
                        finding.cvss_score = 7.5
                        finding.cvss_vector = (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        )
                        await persist_results(
                            self.event_bus,
                            [finding],
                            {
                                "session_id": session_id or str(DEFAULT_SESSION_ID),
                                "method": method,
                                "url": url,
                                "request_headers": {},
                                "request_body": None,
                            },
                            "content_discovery",
                            source="active",
                        )
                    return {
                        "url": url,
                        "path": raw_path,
                        "method": method,
                        "status_code": resp.status_code,
                        "size": len(resp.content),
                        "time_ms": elapsed_ms,
                    }
                return None

            async def worker(base_url: str, raw_path: str, method: str) -> None:
                nonlocal completed
                async with semaphore:
                    result = await check_path(base_url, raw_path, method)
                if result is not None:
                    discovered.append(result)
                if throttle_ms > 0:
                    await asyncio.sleep(throttle_ms / 1000)
                async with completed_lock:
                    completed += 1
                    if completed % 25 == 0:
                        await self.event_bus.publish({
                            "type": "content_discovery.progress",
                            "job_id": str(job_id),
                            "completed": completed,
                            "total": total,
                            "discovered_count": len(discovered),
                        })

            async def scan_base(base_url: str) -> None:
                tasks = [
                    asyncio.create_task(worker(base_url, line + ext, method))
                    for line in lines
                    for ext in extensions
                    for method in methods
                ]
                for task in tasks:
                    await task

            await scan_base(target_url)

            # ── Optional recursion ───────────────────────────────────────
            # Only directories that actually answered are expanded, and at most
            # a handful of them: blind recursion over a wordlist is quadratic.
            if recursive and max_depth > 1 and job_id not in self._cancel_flags:
                dirs = [
                    item["url"]
                    for item in discovered
                    if item["status_code"] in (200, 301, 302, 403)
                    and item["path"].rstrip("/").rsplit("/", 1)[-1].lower()
                    in {"admin", "api", "backup", "backups", "config", "dev",
                        "download", "files", "images", "includes", "js", "old",
                        "private", "static", "uploads", "v1", "v2"}
                ][:10]
                for directory in dirs:
                    if job_id in self._cancel_flags:
                        break
                    await scan_base(directory)

        cancelled = job_id in self._cancel_flags
        self._cancel_flags.discard(job_id)

        return {
            "job_id": str(job_id),
            "target_url": target_url,
            "discovered": discovered,
            "total": total,
            "completed": completed,
            "status": "cancelled" if cancelled else "done",
        }

    def stop(self, job_id: str):
        self._cancel_flags.add(uuid.UUID(job_id))

    def get_status(self, job_id: str) -> dict:
        return {
            "job_id": job_id,
            "is_cancelled": uuid.UUID(job_id) in self._cancel_flags,
        }
