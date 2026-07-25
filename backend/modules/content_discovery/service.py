import asyncio
import uuid
import logging
import time
from pathlib import Path
import httpx
from core.events.bus import EventBus

logger = logging.getLogger(__name__)

MAX_WORDLIST_SIZE = 100_000


class ContentDiscoveryService:
    def __init__(self, event_bus: EventBus, wordlists_dir: str | Path | None = None):
        self.event_bus = event_bus
        self._cancel_flags: set[uuid.UUID] = set()
        if wordlists_dir:
            self.wordlists_dir = Path(wordlists_dir)
        else:
            self.wordlists_dir = Path(__file__).parent.parent.parent / "wordlists"

    def list_wordlists(self) -> list[str]:
        files = []
        if self.wordlists_dir.exists():
            for f in sorted(self.wordlists_dir.iterdir()):
                if f.is_file() and f.suffix == ".txt":
                    files.append(str(f.resolve()))
        return files

    async def discover(
        self,
        target_url: str,
        wordlist_path: str,
        extensions: list[str] | None = None,
        methods: list[str] | None = None,
        throttle_ms: int = 0,
        session_id: str | None = None,
    ) -> dict:
        job_id = uuid.uuid4()
        if extensions is None:
            extensions = [""]
        if methods is None:
            methods = ["GET"]

        if ".." in wordlist_path:
            return {"job_id": str(job_id), "error": "Path traversal blocked"}

        p = Path(wordlist_path)
        wordlist_file = p if p.is_absolute() else (self.wordlists_dir / wordlist_path)

        if not wordlist_file.exists() or not wordlist_file.is_file():
            return {"job_id": str(job_id), "error": f"Wordlist not found: {wordlist_path}"}
        if wordlist_file.suffix not in (".txt",):
            return {"job_id": str(job_id), "error": "Only .txt wordlists are supported"}

        lines = [
            line.strip()
            for line in wordlist_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if len(lines) > MAX_WORDLIST_SIZE:
            lines = lines[:MAX_WORDLIST_SIZE]

        total = len(lines) * len(extensions) * len(methods)
        discovered = []
        completed = 0

        async def check_path(base_url: str, raw_path: str, method: str) -> dict | None:
            if job_id in self._cancel_flags:
                return None

            path = raw_path
            url = base_url.rstrip("/") + "/" + path.lstrip("/")

            try:
                start = time.monotonic()
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    resp = await client.request(method, url, follow_redirects=False)
                elapsed_ms = int((time.monotonic() - start) * 1000)

                if resp.status_code != 404:
                    return {
                        "url": url,
                        "path": path,
                        "method": method,
                        "status_code": resp.status_code,
                        "size": len(resp.content),
                        "time_ms": elapsed_ms,
                    }
            except Exception as e:
                logger.debug("Request failed for %s %s: %s", method, url, e)

            return None

        tasks = []
        for line in lines:
            for ext in extensions:
                path_with_ext = line + ext
                for method in methods:
                    tasks.append((line, ext, method, path_with_ext))

        for line, ext, method, path_with_ext in tasks:
            if job_id in self._cancel_flags:
                break

            result = await check_path(target_url, path_with_ext, method)
            if result is not None:
                discovered.append(result)

            completed += 1

            if completed % 50 == 0 or completed == total:
                await self.event_bus.publish({
                    "type": "content_discovery.progress",
                    "job_id": str(job_id),
                    "completed": completed,
                    "total": total,
                    "discovered_count": len(discovered),
                })

            if throttle_ms > 0:
                await asyncio.sleep(throttle_ms / 1000)

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

    async def _check_path(self, base_url: str, path: str, method: str) -> dict:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            start = time.monotonic()
            async with httpx.AsyncClient(verify=False, timeout=10) as client:
                resp = await client.request(method, url, follow_redirects=False)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {
                "url": url,
                "path": path,
                "method": method,
                "status_code": resp.status_code,
                "size": len(resp.content),
                "time_ms": elapsed_ms,
            }
        except Exception as e:
            return {
                "url": url,
                "path": path,
                "method": method,
                "status_code": 0,
                "size": 0,
                "time_ms": 0,
                "error": str(e),
            }
