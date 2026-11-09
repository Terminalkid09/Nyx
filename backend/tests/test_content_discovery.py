"""Content discovery: soft-404 handling, authorization and wordlist management."""
import httpx
import pytest

from core.events.bus import EventBus
from modules.content_discovery.service import ContentDiscoveryService


def make_handler(requests):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        requests.append(path)
        if path.startswith("/nyx-not-found"):
            # Soft-404 app: unknown paths answer 200 with a generic page.
            return httpx.Response(200, text=f"<html>missing {path} page</html>")
        if path == "/.env":
            return httpx.Response(200, text="DB_PASSWORD=secret\n")
        if path == "/real":
            return httpx.Response(200, text="<html>real page</html>")
        if path == "/soft":
            return httpx.Response(200, text=f"<html>missing {path} page</html>")
        return httpx.Response(404, text="not found")

    return handler


@pytest.fixture(autouse=True)
def allow(monkeypatch):
    async def _allow(session_id, url):
        return True, None, None

    monkeypatch.setattr("modules.content_discovery.service.authorize", _allow)


@pytest.mark.asyncio
async def test_discovers_real_path_and_ignores_soft_404(tmp_path):
    requests = []
    service = ContentDiscoveryService(
        EventBus(), wordlists_dir=tmp_path,
        transport=httpx.MockTransport(make_handler(requests)),
    )
    (tmp_path / "wl.txt").write_text("real\nmissing\nsoft\n", encoding="utf-8")

    result = await service.discover(
        "https://example.com/", "wl.txt", concurrency=4,
    )

    paths = {item["path"] for item in result["discovered"]}
    assert paths == {"real"}
    assert result["total"] == 3
    assert result["completed"] == 3


@pytest.mark.asyncio
async def test_blocked_target_sends_no_request(tmp_path, monkeypatch):
    async def _deny(session_id, url):
        return False, "roe", "not_targeted"

    monkeypatch.setattr("modules.content_discovery.service.authorize", _deny)
    requests = []
    service = ContentDiscoveryService(
        EventBus(), wordlists_dir=tmp_path,
        transport=httpx.MockTransport(make_handler(requests)),
    )
    (tmp_path / "wl.txt").write_text("real\n", encoding="utf-8")

    result = await service.discover("https://example.com/", "wl.txt")

    assert result["status"] == "blocked"
    assert requests == []


@pytest.mark.asyncio
async def test_excluded_generated_path_is_not_requested(tmp_path, monkeypatch):
    requests = []

    async def conditional(session_id, url):
        if url.endswith("/.env"):
            return False, "roe", "excluded"
        return True, None, None

    monkeypatch.setattr(
        "modules.content_discovery.service.authorize", conditional
    )
    service = ContentDiscoveryService(
        EventBus(), wordlists_dir=tmp_path,
        transport=httpx.MockTransport(make_handler(requests)),
    )
    (tmp_path / "wl.txt").write_text(".env\nreal\n", encoding="utf-8")

    result = await service.discover("https://example.com/", "wl.txt")

    assert "/.env" not in requests
    assert {item["path"] for item in result["discovered"]} == {"real"}


def test_wordlist_save_preview_delete(tmp_path):
    service = ContentDiscoveryService(EventBus(), wordlists_dir=tmp_path)

    saved = service.save_wordlist("mine.txt", "a\nb\na\n# comment\n")
    assert saved["lines"] == 2
    assert (tmp_path / "mine.txt").read_text(encoding="utf-8").split() == ["a", "b"]

    preview = service.preview_wordlist("mine.txt", limit=1)
    assert preview["lines"] == 2
    assert preview["preview"] == ["a"]

    listed = service.wordlist_metadata()
    assert [item["name"] for item in listed] == ["mine.txt"]
    assert listed[0]["lines"] == 2

    assert "error" in service.delete_wordlist("missing.txt")
    assert service.delete_wordlist("mine.txt")["deleted"] == "mine.txt"


def test_wordlist_rejects_traversal_and_empty(tmp_path):
    service = ContentDiscoveryService(EventBus(), wordlists_dir=tmp_path)

    assert "error" in service.save_wordlist("../evil.txt", "a\n")
    assert "error" in service.save_wordlist("no-extension", "a\n")
    assert "error" in service.save_wordlist("empty.txt", "\n\n")
    assert not (tmp_path.parent / "evil.txt").exists()


@pytest.mark.asyncio
async def test_sensitive_file_finding_is_persisted(tmp_path):
    from sqlalchemy import select

    from core.storage.database import AsyncSessionLocal
    from core.storage.models import Finding

    service = ContentDiscoveryService(
        EventBus(), wordlists_dir=tmp_path,
        transport=httpx.MockTransport(make_handler([])),
    )
    (tmp_path / "secrets.txt").write_text(".env\n", encoding="utf-8")

    await service.discover("https://example.com/", "secrets.txt")

    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Finding).where(Finding.module == "content_discovery")
            )
        ).scalars().all()
    assert any("Sensitive File Exposed: .env" == row.title for row in rows)
